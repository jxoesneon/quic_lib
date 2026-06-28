import 'dart:typed_data';

import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/streams/quic_stream.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

/// Integration tests for the QUIC packet pipeline (build → send → receive → dispatch).
void main() {
  group('Packet Pipeline', () {
    late QuicConnection conn;
    late CryptoFrameAssembler cryptoAssembler;
    late HandshakeStateMachine handshakeMachine;

    setUp(() {
      cryptoAssembler = CryptoFrameAssembler();
      handshakeMachine = HandshakeStateMachine(HandshakeRole.server);
      conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
        cryptoAssembler: cryptoAssembler,
        handshakeMachine: handshakeMachine,
      );
    });

    test('buildPacket creates and tracks a sent packet', () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      final dcid = conn.cidManager.issueNewId().connectionId;
      final packet = conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 0, data: [0x01, 0x00, 0x00, 0x05])
        ],
        dcid: dcid,
      );

      expect(packet, isNotEmpty);
      expect(conn.sentPacketTracker.getUnackedPackets(0), isNotEmpty);
    });

    test('processIncomingDatagram dispatches ACK frames to recovery', () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(100); // Seed anti-amplification budget

      // Build an ACK frame packet in Initial space (long header = explicit DCID len)
      final dcid = conn.cidManager.issueNewId().connectionId;
      final packet = conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [AckFrame(largestAcknowledged: 5, ackRanges: [])],
        dcid: dcid,
      );

      // Process it as incoming
      final processed = conn.processIncomingDatagram(packet);
      expect(processed, equals(1));
    });

    test('processIncomingDatagram dispatches CRYPTO frames to assembler', () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.onBytesReceived(100);

      final dcid = conn.cidManager.issueNewId().connectionId;
      final cryptoData = Uint8List.fromList([0x01, 0x00, 0x00, 0x05]);
      final packet = conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [CryptoFrame(offset: 0, data: cryptoData)],
        dcid: dcid,
      );

      expect(cryptoAssembler.nextOffset, equals(0));
      conn.processIncomingDatagram(packet);
      // Assembler consumed the CRYPTO frame and produced a contiguous message.
      expect(cryptoAssembler.nextOffset, equals(cryptoData.length));
    });

    test('processIncomingDatagram dispatches STREAM frames to StreamManager',
        () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(100);

      // Use a fixed 8-byte DCID so short-header detection works.
      final dcid = List<int>.filled(8, 0xAB);
      final streamData =
          Uint8List.fromList([0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
      final packet = conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(
            streamId: 0, // client bidi
            data: streamData,
            fin: false,
            offset: 0,
          ),
        ],
        dcid: dcid,
      );

      conn.processIncomingDatagram(packet);
      final stream = conn.streamManager.getStream(0);
      expect(stream, isNotNull);
      expect(stream is QuicReceiveStream, isTrue);
    });

    test('processIncomingDatagram transitions to draining on CONNECTION_CLOSE',
        () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      conn.onBytesReceived(100);

      // Use a fixed 8-byte DCID for reliable short-header parsing.
      final dcid = List<int>.filled(8, 0xAB);
      final packet = conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [
          ConnectionCloseFrame(
              errorCode: 0x0100,
              offendingFrameType: 0x00,
              reasonPhrase: 'test close')
        ],
        dcid: dcid,
      );

      expect(conn.state, equals(ConnectionState.established));
      conn.processIncomingDatagram(packet);
      expect(conn.state, equals(ConnectionState.draining));
    });

    test('processIncomingDatagram coalesced packets are processed separately',
        () {
      conn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      conn.onBytesReceived(100);

      // Build two separate packets
      final dcid = conn.cidManager.issueNewId().connectionId;
      final packet1 = conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 0, data: [0x01])
        ],
        dcid: dcid,
      );
      final packet2 = conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 1, data: [0x02])
        ],
        dcid: dcid,
      );

      // Coalesce them into one datagram
      final coalesced = Uint8List(packet1.length + packet2.length);
      coalesced.setRange(0, packet1.length, packet1);
      coalesced.setRange(packet1.length, coalesced.length, packet2);

      final processed = conn.processIncomingDatagram(coalesced);
      expect(processed, equals(2));
      expect(cryptoAssembler.nextOffset, equals(2));
    });

    test('buildPacket respects anti-amplification before validation', () {
      // Don't call onBytesReceived — budget should be zero
      expect(conn.canSend(10), isFalse);
      conn.onBytesReceived(100);
      // 100 bytes received → can send up to 300 bytes (3x limit)
      expect(conn.canSend(300), isTrue);
      expect(conn.canSend(301), isFalse);
    });
  });
}

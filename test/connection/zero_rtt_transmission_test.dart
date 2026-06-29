import 'dart:typed_data';

import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:test/test.dart';

void main() {
  group('QuicConnection 0-RTT', () {
    QuicConnection createConnection({KeyManager? keyManager}) {
      return QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
        keyManager: keyManager,
      );
    }

    test('canSendZeroRtt is false without keys', () {
      final conn = createConnection();
      expect(conn.canSendZeroRtt, isFalse);
    });

    test('canSendZeroRtt is true after deriveZeroRtt', () async {
      final backend = DefaultCryptoBackend();
      final psk = SimpleSecretKey([0xAB, 0xCD]);
      final keyManager = await KeyManager.deriveZeroRtt(psk, backend);

      final conn = createConnection(keyManager: keyManager);
      expect(conn.canSendZeroRtt, isTrue);
    });

    test('buildZeroRttPacket throws when no keys are available', () {
      final conn = createConnection();
      expect(
        () => conn.buildZeroRttPacket(
          frames: [PaddingFrame()],
          dcid: [0x01, 0x02, 0x03, 0x04],
        ),
        throwsStateError,
      );
    });

    test('buildZeroRttPacket returns bytes when keys are available', () async {
      final backend = DefaultCryptoBackend();
      final psk = SimpleSecretKey([0xAB, 0xCD]);
      final keyManager = await KeyManager.deriveZeroRtt(psk, backend);

      final conn = createConnection(keyManager: keyManager);

      final packet = await conn.buildZeroRttPacket(
        frames: [PaddingFrame(length: 64)],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );

      expect(packet, isA<Uint8List>());
      expect(packet.isNotEmpty, isTrue);
    });

    test('openBidirectionalStream marks stream as early data when 0-RTT keys exist',
        () async {
      final backend = DefaultCryptoBackend();
      final psk = SimpleSecretKey([0xAB, 0xCD]);
      final keyManager = await KeyManager.deriveZeroRtt(psk, backend);

      final conn = createConnection(keyManager: keyManager);
      final streamId = conn.openBidirectionalStream();

      final stream = conn.streamManager.getStream(streamId)!;
      expect(stream.isEarlyData, isTrue);
    });

    test('dispatching a STREAM frame from a 0-RTT packet marks stream as early data',
        () async {
      final conn = createConnection();
      final dcid = List<int>.filled(8, 0x01);
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeZeroRtt,
        destinationConnectionId: dcid,
        sourceConnectionId: const [],
        packetNumber: 0,
      );
      final packet = await PacketBuilder.build(header, [
        StreamFrame(streamId: 0, data: Uint8List.fromList([1, 2, 3]), fin: false),
      ]);

      conn.processIncomingDatagram(packet);

      final stream = conn.streamManager.getStream(0)!;
      expect(stream.isEarlyData, isTrue);
    });

    test('dispatching a STREAM frame from a 1-RTT packet does not mark stream as early data',
        () async {
      final conn = createConnection();
      final dcid = List<int>.filled(8, 0x01);
      final header = ShortHeader(
        destinationConnectionId: dcid,
        packetNumber: 0,
        packetNumberLength: 1,
      );
      final packet = await PacketBuilder.build(header, [
        StreamFrame(streamId: 0, data: Uint8List.fromList([1, 2, 3]), fin: false),
      ]);

      conn.processIncomingDatagram(packet);

      final stream = conn.streamManager.getStream(0)!;
      expect(stream.isEarlyData, isFalse);
    });
  });
}

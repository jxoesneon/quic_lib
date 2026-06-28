import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/sent_packet_tracker.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/frame.dart';

QuicConnection _createConnection({ConnectionStateMachine? stateMachine}) {
  return QuicConnection(
    stateMachine: stateMachine ?? ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
  );
}

void main() {
  group('QuicConnection coverage gaps', () {
    test('isEstablished returns true when in established state', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = _createConnection(stateMachine: sm);
      expect(conn.isEstablished, isTrue);
    });

    test('isClosed returns true when in closed state', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.closed);
      final conn = _createConnection(stateMachine: sm);
      expect(conn.isClosed, isTrue);
    });

    test('abort transitions to closed', () {
      final conn = _createConnection();
      conn.abort();
      expect(conn.state, equals(ConnectionState.closed));
      expect(conn.isClosed, isTrue);
    });

    test('openBidirectionalStream returns sequential IDs 0, 4, 8...', () {
      final conn = _createConnection();
      expect(conn.openBidirectionalStream(), equals(0));
      expect(conn.openBidirectionalStream(), equals(4));
      expect(conn.openBidirectionalStream(), equals(8));
    });

    test('openUnidirectionalStream returns sequential IDs 2, 6, 10...', () {
      final conn = _createConnection();
      expect(conn.openUnidirectionalStream(), equals(2));
      expect(conn.openUnidirectionalStream(), equals(6));
      expect(conn.openUnidirectionalStream(), equals(10));
    });

    test('allocatePacketNumber for handshake space', () {
      final conn = _createConnection();
      final pn1 = conn.allocatePacketNumber(PacketNumberSpace.handshake);
      final pn2 = conn.allocatePacketNumber(PacketNumberSpace.handshake);
      expect(pn1, equals(0));
      expect(pn2, equals(pn1 + 1));
    });

    test('allocatePacketNumber for application space', () {
      final conn = _createConnection();
      final pn1 = conn.allocatePacketNumber(PacketNumberSpace.application);
      final pn2 = conn.allocatePacketNumber(PacketNumberSpace.application);
      expect(pn1, equals(0));
      expect(pn2, equals(pn1 + 1));
    });

    test('onAckReceived with sample ranges', () {
      final conn = _createConnection();
      final info = SentPacketInfo(
        packetNumber: 5,
        sentTimeUs: 1000,
        sizeInBytes: 100,
        frames: [0x01],
        space: 0,
      );
      conn.sentPacketTracker.track(info);
      conn.onAckReceived(0, 5, [(gap: 0, length: 1)]);
      expect(conn.sentPacketTracker.getLargestAcked(0), equals(5));
    });

    test('close when already closed is no-op', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.closed);
      final conn = _createConnection(stateMachine: sm);
      expect(conn.state, equals(ConnectionState.closed));
      conn.close(); // should not throw
      expect(conn.state, equals(ConnectionState.closed));
    });

    test('sentPacketTracker getter', () {
      final conn = _createConnection();
      expect(conn.sentPacketTracker, isA<SentPacketTracker>());
    });
  });

  group('PacketReceiver coverage gaps', () {
    test('processDatagram with single packet (not coalesced)', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = [PingFrame()];
      final packet = PacketBuilder.build(header, frames);
      final results = PacketReceiver.processDatagram(packet);
      expect(results.length, equals(1));
      expect(results.first.header, isA<LongHeader>());
    });

    test('processPacket with VersionNegotiationPacket returns null', () {
      final packet = VersionNegotiationPacket(
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        supportedVersions: [0x00000001],
      ).serialize();
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNull);
    });

    test('processPacket with Retry packet returns null', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xAB],
      );
      final packet = PacketBuilder.build(header, []);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNull);
    });

    test('processPacket with frame parse errors breaks loop', () {
      final shortHeader = ShortHeader(
        destinationConnectionId: [1, 2, 3, 4, 5, 6, 7, 8],
        packetNumber: 0,
        packetNumberLength: 1,
      );
      final shortPacket = PacketBuilder.build(shortHeader, []);
      final badPacket = Uint8List.fromList([...shortPacket, 0xFF, 0xFF]);
      final result = PacketReceiver.processPacket(badPacket);
      expect(result, isNotNull);
      expect(result!.frames, isEmpty);
    });

    test('spaceFromHeader with 0-RTT packet', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      expect(
        PacketReceiver.spaceFromHeader(header),
        equals(PacketNumberSpace.application),
      );
    });

    test('_detectDcidLength with long header (indirect via processPacket)', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04],
        packetNumber: 0,
        token: const [],
      );
      final packet = PacketBuilder.build(header, [PingFrame()]);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(
          result!.header.destinationConnectionId, equals([0x01, 0x02, 0x03]));
    });

    test('_detectDcidLength with short header (indirect via processPacket)',
        () {
      final header = ShortHeader(
        destinationConnectionId: [1, 2, 3, 4, 5, 6, 7, 8],
        packetNumber: 0,
        packetNumberLength: 1,
      );
      final packet = PacketBuilder.build(header, [PingFrame()]);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header.destinationConnectionId,
          equals([1, 2, 3, 4, 5, 6, 7, 8]));
    });

    test('_headerLength for LongHeader (indirect via processPacket)', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = [PingFrame(), PingFrame()];
      final packet = PacketBuilder.build(header, frames);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.frames.length, equals(2));
    });

    test('_headerLength for ShortHeader (indirect via processPacket)', () {
      final header = ShortHeader(
        destinationConnectionId: [1, 2, 3, 4, 5, 6, 7, 8],
        packetNumber: 42,
        packetNumberLength: 2,
      );
      final frames = [PingFrame()];
      final packet = PacketBuilder.build(header, frames);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header, isA<ShortHeader>());
      expect((result.header as ShortHeader).packetNumber, equals(42));
      expect(result.frames.length, equals(1));
    });
  });
}

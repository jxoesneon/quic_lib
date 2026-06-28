import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/streams/stream_scheduler.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/quic_versions.dart';

void main() {
  group('QuicConnection', () {
    QuicConnection _createConnection({
      ConnectionStateMachine? stateMachine,
      ConnectionIdManager? cidManager,
    }) {
      return QuicConnection(
        stateMachine: stateMachine ?? ConnectionStateMachine(),
        cidManager: cidManager ?? ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
    }

    test('construction with all subsystems', () {
      final conn = _createConnection();
      expect(conn, isNotNull);
    });

    test('initial state is idle', () {
      final conn = _createConnection();
      expect(conn.state, equals(ConnectionState.idle));
      expect(conn.isEstablished, isFalse);
      expect(conn.isClosed, isFalse);
    });

    test('isEstablished and isClosed reflect state machine', () {
      final sm = ConnectionStateMachine();
      final conn = _createConnection(stateMachine: sm);
      sm.transitionTo(ConnectionState.handshaking);
      expect(conn.isEstablished, isFalse);
      sm.transitionTo(ConnectionState.established);
      expect(conn.isEstablished, isTrue);
      sm.transitionTo(ConnectionState.closing);
      expect(conn.isClosed, isFalse);
      sm.transitionTo(ConnectionState.closed);
      expect(conn.isClosed, isTrue);
    });

    test('connectionId returns null when no IDs are active', () {
      final conn = _createConnection();
      expect(conn.connectionId, isNull);
    });

    test('connectionId returns first active ID', () {
      final cidManager = ConnectionIdManager();
      cidManager.issueNewId();
      final conn = _createConnection(cidManager: cidManager);
      expect(conn.connectionId, isNotNull);
      expect(conn.connectionId!.length, greaterThanOrEqualTo(8));
    });

    test('openBidirectionalStream returns valid stream ID', () {
      final conn = _createConnection();
      final id = conn.openBidirectionalStream();
      expect(id, equals(0)); // First client bidi
      expect(StreamId.isBidirectional(id), isTrue);
      expect(StreamId.isClientInitiated(id), isTrue);
    });

    test('openUnidirectionalStream returns valid stream ID', () {
      final conn = _createConnection();
      final id = conn.openUnidirectionalStream();
      expect(id, equals(2)); // First client uni
      expect(StreamId.isUnidirectional(id), isTrue);
      expect(StreamId.isClientInitiated(id), isTrue);
    });

    test('close transitions to closing', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = _createConnection(stateMachine: sm);
      conn.close();
      expect(conn.state, equals(ConnectionState.closing));
    });

    test('close is no-op when already closing', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = _createConnection(stateMachine: sm);
      conn.close();
      expect(conn.state, equals(ConnectionState.closing));
      // Should not throw
      conn.close();
      expect(conn.state, equals(ConnectionState.closing));
    });

    test('close is no-op when already closed', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.closed);
      final conn = _createConnection(stateMachine: sm);
      expect(conn.isClosed, isTrue);
      conn.close();
      expect(conn.state, equals(ConnectionState.closed));
    });

    test('abort transitions directly to closed', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      final conn = _createConnection(stateMachine: sm);
      conn.abort();
      expect(conn.isClosed, isTrue);
    });

    test('allocatePacketNumber returns sequential numbers', () {
      final conn = _createConnection();
      final pn1 = conn.allocatePacketNumber(PacketNumberSpace.initial);
      final pn2 = conn.allocatePacketNumber(PacketNumberSpace.initial);
      expect(pn2, equals(pn1 + 1));
    });

    test('subsystems are accessible', () {
      final conn = _createConnection();
      expect(conn.cidManager, isA<ConnectionIdManager>());
      expect(conn.rttEstimator, isA<RttEstimator>());
      expect(conn.lossDetector, isA<LossDetector>());
      expect(conn.ptoScheduler, isA<PtoScheduler>());
      expect(conn.congestionController, isA<CongestionController>());
      expect(conn.pacingCalculator, isNotNull);
      expect(conn.sentPacketTracker, isNotNull);
      expect(conn.recoveryManager, isNotNull);
      expect(conn.streamManager, isNotNull);
      expect(conn.connectionFlowController, isNotNull);
      expect(conn.stateMachine, isA<ConnectionStateMachine>());
    });

    test('cryptoAssembler and handshakeMachine are null by default', () {
      final conn = _createConnection();
      expect(conn.cryptoAssembler, isNull);
      expect(conn.handshakeMachine, isNull);
      expect(conn.keyManager, isNull);
    });

    test('streamScheduler setter updates scheduler', () {
      final conn = _createConnection();
      final scheduler = _TestStreamScheduler();
      conn.streamScheduler = scheduler;
      expect(conn.streamManager, isNotNull);
    });

    test('pacing getters when not pacing', () {
      final conn = _createConnection();
      expect(conn.shouldPacePackets, isFalse);
      expect(conn.pacingDelayUs, isNull);
    });

    test('canSend respects anti-amplification limit before validation', () {
      final conn = _createConnection();
      // No bytes received yet, so send budget is 0.
      expect(conn.canSend(1), isFalse);

      // Receive 100 bytes → budget = 300.
      conn.onBytesReceived(100);
      expect(conn.canSend(300), isTrue);
      expect(conn.canSend(301), isFalse);
    });

    test('validateAddress removes anti-amplification limit', () {
      final conn = _createConnection();
      conn.onBytesReceived(100);
      expect(conn.canSend(1000), isFalse);

      conn.validateAddress();
      expect(conn.canSend(1000), isTrue);
    });

    test('onBytesSent reduces send budget', () {
      final conn = _createConnection();
      conn.onBytesReceived(100);
      expect(conn.sendBudget, equals(300));
      conn.onBytesSent(50);
      expect(conn.sendBudget, equals(250));
    });

    test('sendBudget is zero initially', () {
      final conn = _createConnection();
      expect(conn.sendBudget, equals(0));
    });

    test('onAckReceived does not throw', () {
      final conn = _createConnection();
      conn.onAckReceived(
        PacketNumberSpace.initial.spaceIndex,
        5,
        [(gap: 0, length: 2)],
      );
    });

    test('onPacketSent does not throw', () {
      final conn = _createConnection();
      conn.onPacketSent(
        1,
        DateTime.now().millisecondsSinceEpoch * 1000,
        ackEliciting: true,
        sizeInBytes: 1200,
        spaceIndex: PacketNumberSpace.initial.spaceIndex,
      );
    });

    test('isPtoExpired returns false before any packets sent', () {
      final conn = _createConnection();
      expect(conn.isPtoExpired(0), isFalse);
    });

    test('onPtoFired does not throw', () {
      final conn = _createConnection();
      conn.onPtoFired(DateTime.now().millisecondsSinceEpoch * 1000);
    });

    test('migrationHelper is accessible', () {
      final conn = _createConnection();
      expect(conn.migrationHelper, isNotNull);
    });

    test('getPendingChallenge returns null initially', () {
      final conn = _createConnection();
      expect(conn.getPendingChallenge(), isNull);
    });

    test('isPathValidated returns false for unknown path', () {
      final conn = _createConnection();
      expect(conn.isPathValidated([0x01, 0x02]), isFalse);
    });

    test('onPathValidated increments validatedPathCount', () {
      final conn = _createConnection();
      expect(conn.validatedPathCount, equals(0));
      conn.onPathValidated();
      expect(conn.validatedPathCount, equals(1));
    });

    test('processIncomingDatagram with empty data returns 0', () {
      final conn = _createConnection();
      expect(conn.processIncomingDatagram(Uint8List(0)), equals(0));
    });

    test('processIncomingDatagram with valid Initial packet', () async {
      final conn = _createConnection();
      final header = LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: [0x01], // PING frame
      );
      final packet = await header.serialize();
      expect(conn.processIncomingDatagram(packet), equals(1));
    });

    test('processIncomingDatagram with coalesced packets', () async {
      final conn = _createConnection();
      final header1 = LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: [0x01], // PING frame
      );
      final header2 = LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: [0x01], // PING frame
      );
      final packet1 = await header1.serialize();
      final packet2 = await header2.serialize();
      final datagram = Uint8List(packet1.length + packet2.length);
      datagram.setRange(0, packet1.length, packet1);
      datagram.setRange(packet1.length, datagram.length, packet2);

      expect(conn.processIncomingDatagram(datagram), equals(2));
    });

    test('_dispatchFrames handles ConnectionCloseFrame', () async {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = _createConnection(stateMachine: sm);
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: ConnectionCloseFrame(errorCode: 0).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
      expect(conn.state, equals(ConnectionState.draining));
    });

    test('_dispatchFrames handles ApplicationCloseFrame', () async {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = _createConnection(stateMachine: sm);
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: ApplicationCloseFrame(errorCode: 0).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
      expect(conn.state, equals(ConnectionState.draining));
    });

    test('_dispatchFrames handles PathChallengeFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: PathChallengeFrame(data: [1, 2, 3, 4, 5, 6, 7, 8]).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
      expect(conn.getPendingChallenge(), isNotNull);
    });

    test('_dispatchFrames handles MaxDataFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: MaxDataFrame(maxData: 65536).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles MaxStreamDataFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload:
            MaxStreamDataFrame(streamId: 0, maxStreamData: 65536).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles MaxStreamsFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: MaxStreamsFrame(maxStreams: 16, isUnidirectional: false)
            .serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles NewConnectionIdFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: NewConnectionIdFrame(
          sequenceNumber: 0,
          retirePriorTo: 0,
          connectionId: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8],
          statelessResetToken: List<int>.generate(16, (i) => i),
        ).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
      expect(conn.activeConnectionIdCount, equals(1));
    });

    test('_dispatchFrames handles RetireConnectionIdFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: RetireConnectionIdFrame(sequenceNumber: 0).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles StreamFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: StreamFrame(streamId: 0, data: [0xAB, 0xCD]).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles HandshakeDoneFrame', () async {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      final conn = _createConnection(stateMachine: sm);
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: HandshakeDoneFrame().serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
      expect(conn.isEstablished, isTrue);
    });

    test('_dispatchFrames handles PingFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: PingFrame().serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles PaddingFrame', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: PaddingFrame().serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_dispatchFrames handles unknown frame types gracefully', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: [0x30],
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('_handleCryptoFrame fallback to assembler when no handler', () async {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
        cryptoAssembler: CryptoFrameAssembler(),
      );
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: CryptoFrame(offset: 0, data: [0x01, 0x02]).serialize(),
      ).serialize();
      conn.processIncomingDatagram(packet);
    });

    test('processEncryptedDatagram with 0-RTT long header packet', () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: PingFrame().serialize(),
      ).serialize();
      expect(await conn.processEncryptedDatagram(packet), equals(1));
    });

    test('processEncryptedDatagram with Handshake long header packet',
        () async {
      final conn = _createConnection();
      final packet = await LongHeader(
        version: QuicVersions.v1,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06, 0x07, 0x08],
        payload: PingFrame().serialize(),
      ).serialize();
      expect(await conn.processEncryptedDatagram(packet), equals(1));
    });

    test('buildPacket returns non-empty bytes', () async {
      final conn = _createConnection();
      final packet = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [PingFrame()],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(packet.length, greaterThan(0));
    });

    test('buildEncryptedPacket without keyManager falls back to plaintext',
        () async {
      final conn = _createConnection();
      final packet = await conn.buildEncryptedPacket(
        space: PacketNumberSpace.initial,
        frames: [PingFrame()],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(packet.length, greaterThan(0));
    });

    test('processEncryptedDatagram with empty data returns 0', () async {
      final conn = _createConnection();
      expect(await conn.processEncryptedDatagram(Uint8List(0)), equals(0));
    });

    test(
        'spaceFromLongPacketType via processEncryptedDatagram covers all cases',
        () async {
      final conn = _createConnection();
      final initialPacket = Uint8List.fromList([
        0xC3,
        0x00,
        0x00,
        0x00,
        0x01,
        0x04,
        0x01,
        0x02,
        0x03,
        0x04,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x00,
        0x02,
        0x01,
        0x00,
      ]);
      await conn.processEncryptedDatagram(initialPacket);
    });

    test('onAddressValidated transitions to established when handshaking', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      final conn = _createConnection(stateMachine: sm);
      conn.onAddressValidated();
      expect(conn.isEstablished, isTrue);
    });

    test('canSendZeroRtt returns false by default', () {
      final conn = _createConnection();
      expect(conn.canSendZeroRtt, isFalse);
    });

    test('buildZeroRttPacket throws when no keys', () {
      final conn = _createConnection();
      expect(
        () => conn.buildZeroRttPacket(frames: [PingFrame()], dcid: [0x01]),
        throwsA(isA<StateError>()),
      );
    });

    test('generateNewConnectionIdFrame returns a frame', () {
      final conn = _createConnection();
      final frame = conn.generateNewConnectionIdFrame();
      expect(frame, isA<NewConnectionIdFrame>());
    });

    test('activeConnectionIdCount starts at zero', () {
      final conn = _createConnection();
      expect(conn.activeConnectionIdCount, equals(0));
    });

    test('updateConnectionFlowControl updates availableWindow', () {
      final conn = _createConnection();
      conn.updateConnectionFlowControl(131072);
      expect(conn.connectionFlowController.availableWindow, equals(131072));
    });
  });
}

class _TestStreamScheduler implements StreamScheduler {
  @override
  int selectNextStream(List<int> activeStreamIds) => activeStreamIds.first;
}

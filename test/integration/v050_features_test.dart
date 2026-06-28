import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/packet_sender.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/libp2p/peer_id.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/sent_packet_tracker.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/streams/stream_manager.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Integration tests for dart_quic v0.5.0 features.
void main() {
  group('QuicConnection MAX_DATA', () {
    test('receives MAX_DATA and updates connection flow controller', () {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      final windowBefore = conn.connectionFlowController.availableWindow;
      expect(windowBefore, greaterThan(0));

      final packet = PacketSender.buildPacket(
        frames: [MaxDataFrame(maxData: 200000)],
        space: PacketNumberSpace.application,
        dcid: List.filled(8, 0xAB),
        packetNumber: 0,
      );

      final processed = conn.processIncomingDatagram(packet);
      expect(processed, equals(1));

      final windowAfter = conn.connectionFlowController.availableWindow;
      expect(windowAfter, greaterThan(windowBefore));
    });
  });

  group('QuicConnection MAX_STREAM_DATA', () {
    test('stream manager updates send window on MaxStreamDataFrame', () {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      // First create a stream by receiving a STREAM frame.
      final streamPacket = PacketSender.buildPacket(
        frames: [
          StreamFrame(streamId: 0, data: [0x01])
        ],
        space: PacketNumberSpace.application,
        dcid: List.filled(8, 0xAB),
        packetNumber: 0,
      );
      conn.processIncomingDatagram(streamPacket);

      final sendController = conn.streamManager.getSendFlowController(0);
      expect(sendController, isNotNull);
      final windowBefore = sendController!.availableWindow;

      // Now receive a MAX_STREAM_DATA frame for that stream.
      final maxStreamDataPacket = PacketSender.buildPacket(
        frames: [MaxStreamDataFrame(streamId: 0, maxStreamData: 200000)],
        space: PacketNumberSpace.application,
        dcid: List.filled(8, 0xAB),
        packetNumber: 1,
      );
      conn.processIncomingDatagram(maxStreamDataPacket);

      final windowAfter =
          conn.streamManager.getSendFlowController(0)!.availableWindow;
      expect(windowAfter, greaterThan(windowBefore));
    });
  });

  group('Http3Connection.sendSettings', () {
    test('returns a valid Http3SettingsFrame without throwing', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.pendingSettings, isNull);

      final settings = conn.sendSettings();
      expect(settings, isA<Http3SettingsFrame>());
      expect(conn.pendingSettings, equals(settings));
    });
  });

  group('PeerId Base58', () {
    test('encodeBase58 / decodeBase58 round-trip', () {
      final bytes = List<int>.generate(32, (i) => i);
      final peerId = PeerId.fromBytes(bytes);

      final encoded = peerId.encodeBase58();
      expect(encoded, isNotEmpty);

      final decoded = PeerId.decodeBase58(encoded);
      expect(decoded, equals(peerId));
    });
  });

  group('ConnectionIdManager retirePriorTo', () {
    test('issueNewId with retirePriorTo retires older CIDs', () {
      final manager = ConnectionIdManager();

      final id0 = manager.issueNewId();
      final id1 = manager.issueNewId();
      final id2 = manager.issueNewId();

      expect(manager.activeIds, hasLength(3));
      expect(manager.isValidId(id0.connectionId), isTrue);
      expect(manager.isValidId(id1.connectionId), isTrue);
      expect(manager.isValidId(id2.connectionId), isTrue);

      final id3 = manager.issueNewId(retirePriorTo: 2);

      expect(manager.isValidId(id0.connectionId), isFalse);
      expect(manager.isValidId(id1.connectionId), isFalse);
      expect(manager.isValidId(id2.connectionId), isTrue);
      expect(manager.isValidId(id3.connectionId), isTrue);
      expect(manager.activeIds, hasLength(2));
    });
  });

  group('SentPacketTracker', () {
    test('tracks acked packets and removes them from unacked', () {
      final tracker = SentPacketTracker();

      tracker.track(SentPacketInfo(
        packetNumber: 0,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [],
        space: 2,
      ));
      tracker.track(SentPacketInfo(
        packetNumber: 1,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [],
        space: 2,
      ));
      tracker.track(SentPacketInfo(
        packetNumber: 2,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [],
        space: 2,
      ));

      final acked = tracker.onAck(2, 1, []);
      expect(acked, hasLength(2));
      expect(acked.map((i) => i.packetNumber), contains(0));
      expect(acked.map((i) => i.packetNumber), contains(1));
      expect(tracker.getLargestAcked(2), equals(1));

      final unacked = tracker.getUnackedPackets(2);
      expect(unacked, hasLength(1));
      expect(unacked.first.packetNumber, equals(2));
    });
  });

  group('LossDetector', () {
    test('reports loss time after packet sent and ack', () {
      final ld = LossDetector();
      const sentTime = 0;
      const ackTime = 1000000; // 1 second later, in microseconds
      const srtt = 10000; // 10ms

      ld.onPacketSent(0, sentTime);
      ld.onPacketSent(1, sentTime);
      ld.onPacketSent(2, sentTime);

      // ACK only packet 0.
      final lost = ld.onAckReceived(0, ackTime, srtt);

      // Packets 1 and 2 should be declared lost by time threshold.
      expect(lost, contains(1));
      expect(lost, contains(2));
      expect(ld.largestAcked, equals(0));
    });
  });
}

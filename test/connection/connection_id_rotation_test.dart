import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/packet_sender.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('Connection ID rotation', () {
    QuicConnection _createConnection() {
      return QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
    }

    test('generateNewConnectionIdFrame creates a valid frame', () {
      final conn = _createConnection();
      final frame = conn.generateNewConnectionIdFrame();

      expect(frame, isA<NewConnectionIdFrame>());

      final newCidFrame = frame as NewConnectionIdFrame;
      expect(newCidFrame.connectionId, isNotEmpty);
      expect(newCidFrame.statelessResetToken, isNotEmpty);
      expect(newCidFrame.statelessResetToken.length, equals(16));
    });

    test('activeConnectionIdCount reflects the number of active CIDs', () {
      final conn = _createConnection();
      final initialCount = conn.activeConnectionIdCount;

      conn.generateNewConnectionIdFrame();
      conn.generateNewConnectionIdFrame();

      expect(conn.activeConnectionIdCount, equals(initialCount + 2));
    });

    test('NewConnectionIdFrame reception is wired in _dispatchFrames', () {
      final conn = _createConnection();
      final cid = List<int>.filled(8, 0xAB);
      final token = List<int>.filled(16, 0xCD);
      final frame = NewConnectionIdFrame(
        sequenceNumber: 42,
        retirePriorTo: 0,
        connectionId: cid,
        statelessResetToken: token,
      );

      final packet = PacketSender.buildPacket(
        frames: [frame],
        space: PacketNumberSpace.application,
        dcid: List<int>.filled(8, 0x00),
        packetNumber: 0,
      );

      conn.processIncomingDatagram(packet);

      expect(conn.cidManager.isValidId(cid), isTrue);
    });
  });
}

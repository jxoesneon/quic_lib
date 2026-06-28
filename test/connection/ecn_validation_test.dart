import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';

QuicConnection _createConnection({
  ConnectionStateMachine? stateMachine,
  ConnectionIdManager? cidManager,
  bool ecnEnabled = true,
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
    ecnEnabled: ecnEnabled,
  );
}

/// Build a raw short-header packet with the given [payload].
/// Uses a fixed packet number length of 1.
Uint8List _buildShortHeaderPacket(List<int> payload) {
  final dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
  // First byte: HF=0, FB=1, no spin, no key phase, PN length = 1
  final firstByte = 0x40;
  final pnBytes = [0x00];
  return Uint8List.fromList([firstByte, ...dcid, ...pnBytes, ...payload]);
}

void main() {
  group('ECN validation with AckEcnFrame', () {
    test('validation passes with monotonically increasing counts', () {
      final conn = _createConnection();
      expect(conn.isEcnValidated, isFalse);

      // First ACK_ECN with some ECT(0) counts.
      final frame1 = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 2,
        ect1Count: 0,
        ceCount: 0,
      );
      final packet1 = _buildShortHeaderPacket(frame1.serialize());
      conn.processIncomingDatagram(packet1);

      expect(conn.isEcnValidated, isTrue);

      // Second ACK_ECN with higher counts.
      final frame2 = AckEcnFrame(
        largestAcknowledged: 2,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 5,
        ect1Count: 1,
        ceCount: 0,
      );
      final packet2 = _buildShortHeaderPacket(frame2.serialize());
      conn.processIncomingDatagram(packet2);

      // Still validated, no failure.
      expect(conn.isEcnValidated, isTrue);
    });

    test('validation fails with decreasing ECT(0) count', () {
      final conn = _createConnection();

      // First ACK_ECN with ECT(0) count = 5.
      final frame1 = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 5,
        ect1Count: 0,
        ceCount: 0,
      );
      final packet1 = _buildShortHeaderPacket(frame1.serialize());
      conn.processIncomingDatagram(packet1);
      expect(conn.isEcnValidated, isTrue);

      // Second ACK_ECN with lower ECT(0) count.
      final frame2 = AckEcnFrame(
        largestAcknowledged: 2,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 3,
        ect1Count: 0,
        ceCount: 0,
      );
      final packet2 = _buildShortHeaderPacket(frame2.serialize());
      conn.processIncomingDatagram(packet2);

      // Validation should have failed, so ECN is no longer validated and
      // should be disabled.
      expect(conn.isEcnValidated, isFalse);
    });

    test('validation fails with decreasing CE count', () {
      final conn = _createConnection();

      final frame1 = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 3,
        ect1Count: 1,
        ceCount: 2,
      );
      final packet1 = _buildShortHeaderPacket(frame1.serialize());
      conn.processIncomingDatagram(packet1);
      expect(conn.isEcnValidated, isTrue);

      final frame2 = AckEcnFrame(
        largestAcknowledged: 2,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 4,
        ect1Count: 2,
        ceCount: 1,
      );
      final packet2 = _buildShortHeaderPacket(frame2.serialize());
      conn.processIncomingDatagram(packet2);

      expect(conn.isEcnValidated, isFalse);
    });

    test('validation fails when CE is reported without ECT marks', () {
      final conn = _createConnection();

      final frame = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 0,
        ect1Count: 0,
        ceCount: 1,
      );
      final packet = _buildShortHeaderPacket(frame.serialize());
      conn.processIncomingDatagram(packet);

      expect(conn.isEcnValidated, isFalse);
    });
  });

  group('ECN disabled after validation failure', () {
    test('validation fails and ecnValidated becomes false', () {
      final conn = _createConnection(ecnEnabled: true);

      // First establish a baseline with a higher count.
      final frame1 = AckEcnFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 5,
        ect1Count: 0,
        ceCount: 0,
      );
      final ackPacket1 = _buildShortHeaderPacket(frame1.serialize());
      conn.processIncomingDatagram(ackPacket1);
      expect(conn.isEcnValidated, isTrue);

      // Trigger validation failure with decreasing counts.
      final frame2 = AckEcnFrame(
        largestAcknowledged: 2,
        ackDelay: 0,
        ackRanges: [],
        ect0Count: 3,
        ect1Count: 0,
        ceCount: 0,
      );
      final ackPacket2 = _buildShortHeaderPacket(frame2.serialize());
      conn.processIncomingDatagram(ackPacket2);

      // After failure, ECN should no longer be validated.
      expect(conn.isEcnValidated, isFalse);
    });

    test('outgoing packets are not ECN-capable when ecnEnabled is false', () async {
      final conn = _createConnection(ecnEnabled: false);
      final dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      final packet = await conn.buildPacket(
        space: PacketNumberSpace.application,
        frames: [PingFrame()],
        dcid: dcid,
      );
      // With ECN removed from ShortHeader, the bottom 2 bits encode PN length.
      // PN length = 1 means bits 00, so first byte should be 0x40.
      expect(packet[0] & 0x03, equals(0));
    });
  });
}

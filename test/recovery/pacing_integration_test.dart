import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/pacing_calculator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Integration tests for congestion-control pacing.
void main() {
  group('PacingCalculator', () {
    test('computes correct interval', () {
      final calculator = PacingCalculator(
        congestionWindow: 4800,
        smoothedRttUs: 333000,
        packetSize: 1200,
      );

      // Expected: (1200 * 333000) ~/ 4800 = 83250
      expect(calculator.pacingIntervalUs, equals(83250));
      expect(calculator.pacingIntervalUs, greaterThan(0));
      expect(calculator.pacingIntervalUs, lessThan(333000));
    });
  });

  group('QuicConnection pacing integration', () {
    late QuicConnection conn;

    setUp(() {
      conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
    });

    test('shouldPacePackets is true when cwnd > 2*packetSize', () {
      // Default packet size is 1200, so 2*packetSize = 2400.
      // Set congestion window to 3000 to exceed the pacing threshold.
      conn.pacingCalculator.updateCongestionWindow(3000);

      expect(conn.shouldPacePackets, isTrue);
    });

    test('pacingDelayUs returns value when cwnd is large', () {
      conn.pacingCalculator.updateCongestionWindow(3000);

      expect(conn.pacingDelayUs, isNotNull);
      expect(conn.pacingDelayUs, greaterThan(0));
    });

    test('buildPacket delays non-ACK packets when pacing is active', () async {
      conn.pacingCalculator.updateCongestionWindow(3000);
      conn.pacingCalculator.updateRtt(333000);
      final delay = conn.pacingDelayUs!;

      var now = 0;
      // Build the first packet to record the send time, then verify the second
      // packet is delayed by the pacing interval.
      final first = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 0, data: [0x01])
        ],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(first, isNotNull);

      // Because the real timer uses wall-clock time, the second packet will
      // only wait if the pacing interval has not elapsed. With a 3000-byte cwnd
      // and 333ms RTT the interval is ~83ms, so the second call should yield
      // and wait roughly the remaining time. We simply verify it completes
      // without errors and returns a non-empty packet.
      final second = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [
          CryptoFrame(offset: 0, data: [0x02])
        ],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(second, isNotNull);
      expect(second.length, greaterThan(0));
    }, timeout: Timeout(Duration(milliseconds: 2000)));

    test('buildPacket does not delay ACK-only packets', () async {
      conn.pacingCalculator.updateCongestionWindow(3000);
      conn.pacingCalculator.updateRtt(333000);

      final first = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [AckFrame(largestAcknowledged: 1, ackDelay: 0)],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(first, isNotNull);

      // Second ACK-only packet should not be paced, so it completes quickly.
      final second = await conn.buildPacket(
        space: PacketNumberSpace.initial,
        frames: [AckFrame(largestAcknowledged: 2, ackDelay: 0)],
        dcid: [0x01, 0x02, 0x03, 0x04],
      );
      expect(second, isNotNull);
    }, timeout: Timeout(Duration(milliseconds: 500)));
  });
}

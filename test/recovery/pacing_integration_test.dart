import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/recovery/pacing_calculator.dart';
import 'package:dart_quic/src/streams/stream_id.dart';

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
  });
}

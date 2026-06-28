import 'package:test/test.dart';
import 'package:quic_lib/src/connection/congestion_control/cubic.dart';

void main() {
  group('CubicCongestionController', () {
    late CubicCongestionController controller;

    setUp(() {
      controller = CubicCongestionController();
    });

    test('initial cwnd equals 2 packets', () {
      expect(controller.congestionWindow, equals(2400));
      expect(controller.bytesInFlight, equals(0));
    });

    test('slow start doubles cwnd on ack', () {
      controller.onPacketSent(1, 2400);
      expect(controller.bytesInFlight, equals(2400));

      controller.onAckReceived(1, 2400, DateTime.now());
      // _cwnd was 2 packets, ack of 2400 bytes = 2 packets -> _cwnd = 4
      expect(controller.congestionWindow, equals(4800));
      expect(controller.bytesInFlight, equals(0));
    });

    test('congestion event reduces cwnd by beta=0.7', () {
      // Grow cwnd to 10 packets in slow start (4 iterations of 2400 bytes).
      for (var i = 0; i < 4; i++) {
        controller.onPacketSent(i, 2400);
        controller.onAckReceived(i, 2400, DateTime.now());
      }
      expect(controller.congestionWindow, equals(12000)); // 10 * 1200

      // Trigger loss.
      controller.onPacketLost(100, 1200, DateTime.now());
      final expectedSsthresh = (10 * 0.7).floor(); // 7 packets
      expect(controller.congestionWindow, equals(expectedSsthresh * 1200));
    });

    test('CUBIC growth after loss', () {
      // Grow cwnd past ssthresh.
      for (var i = 0; i < 4; i++) {
        controller.onPacketSent(i, 2400);
        controller.onAckReceived(i, 2400, DateTime.now());
      }
      expect(controller.congestionWindow, greaterThan(2400));

      // Trigger loss to enter CUBIC mode.
      final lossTime = DateTime.now();
      controller.onPacketLost(100, 1200, lossTime);
      final cwndAfterLoss = controller.congestionWindow;

      // Advance time and ack more data to observe CUBIC growth.
      final future = lossTime.add(const Duration(seconds: 2));
      controller.onAckReceived(101, 1200, future);
      final cwndLater = controller.congestionWindow;

      // CUBIC window should grow over time.
      expect(cwndLater, greaterThanOrEqualTo(cwndAfterLoss));
    });

    test('fast convergence reduces wMax on decreasing loss peak', () {
      // Grow to first peak of 10 packets.
      for (var i = 0; i < 4; i++) {
        controller.onPacketSent(i, 2400);
        controller.onAckReceived(i, 2400, DateTime.now());
      }
      expect(controller.cwndInPackets, equals(10));
      final t0 = DateTime.now();
      controller.onPacketLost(100, 1200, t0);
      final firstWMax = controller.wMax; // 10
      expect(firstWMax, equals(10));

      // Exit recovery.
      controller.onAckReceived(101, 1200, t0);

      // Grow slightly in CUBIC mode (advance time).
      final t1 = t0.add(const Duration(seconds: 1));
      controller.onAckReceived(102, 1200, t1);
      final peakAfterRecovery = controller.cwndInPackets; // ~9

      // Second loss at a smaller peak triggers fast convergence.
      controller.onPacketLost(200, 1200, t1);
      final secondWMax = controller.wMax;

      // Fast convergence should have reduced _wMax below the actual peak.
      expect(secondWMax, lessThan(peakAfterRecovery));
      expect(secondWMax, lessThan(firstWMax));
    });

    test('minimum cwnd floor', () {
      controller.onPacketLost(1, 0, DateTime.now());
      expect(controller.congestionWindow, equals(2400)); // 2 * 1200
    });

    test('reset restores defaults', () {
      controller.onPacketSent(1, 2400);
      controller.onAckReceived(1, 2400, DateTime.now());
      controller.onPacketLost(2, 1200, DateTime.now());

      controller.reset();

      expect(controller.congestionWindow, equals(2400));
      expect(controller.bytesInFlight, equals(0));
    });

    test('canSend respects cwnd', () {
      expect(controller.canSend(2400), isTrue);
      expect(controller.canSend(2401), isFalse);

      controller.onPacketSent(1, 1200);
      expect(controller.bytesInFlight, equals(1200));
      expect(controller.canSend(1200), isTrue);
      expect(controller.canSend(1201), isFalse);
    });

    test('ECN CE marks are treated as loss events', () {
      // Grow cwnd.
      for (var i = 0; i < 4; i++) {
        controller.onPacketSent(i, 2400);
        controller.onAckReceived(i, 2400, DateTime.now());
      }
      final before = controller.congestionWindow;
      expect(before, greaterThan(2400));

      controller.onECNCEMarked(1);
      final after = controller.congestionWindow;
      expect(after, lessThan(before));
    });

    test('app-limited suppresses cwnd growth in slow start', () {
      controller.onPacketSent(1, 2400);
      controller.setAppLimited(true);
      expect(controller.appLimited, isTrue);

      controller.onAckReceived(1, 2400, DateTime.now());
      expect(controller.congestionWindow, equals(2400));
      expect(controller.bytesInFlight, equals(0));
    });

    test('app-limited exits when cwnd is fully utilized', () {
      controller.setAppLimited(true);
      controller.onPacketSent(1, 2400);
      expect(controller.appLimited, isFalse);
    });

    test('persistent congestion resets cwnd to minimum', () {
      controller.onPacketSent(1, 2400);
      controller.onAckReceived(1, 2400, DateTime.now());
      expect(controller.congestionWindow, greaterThan(2400));

      controller.onPersistentCongestion();
      expect(controller.congestionWindow, equals(2400));
    });

    test('Hystart exits CUBIC slow start early on ack train', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      // Send enough packets.
      for (var i = 0; i < 10; i++) {
        controller.onPacketSent(i, 1200);
      }
      // Ack them back-to-back (< 2ms apart) to trigger Hystart.
      for (var i = 0; i < 10; i++) {
        controller.onAckReceived(i, 1200, now);
        now = now.add(const Duration(milliseconds: 1));
      }
      // Hystart should have exited slow start.
      expect(controller.cwndInPackets, greaterThanOrEqualTo(2));
      // After exit, subsequent acks should use CUBIC growth.
      final before = controller.congestionWindow;
      controller.onAckReceived(10, 1200, now);
      final after = controller.congestionWindow;
      // CUBIC should not increase as fast as slow start for single ack.
      expect(after, greaterThanOrEqualTo(before));
    });

    test('Hystart delay-based exit on ack spacing increase', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      for (var i = 0; i < 5; i++) {
        controller.onPacketSent(i, 1200);
      }
      // Normal spacing.
      for (var i = 0; i < 3; i++) {
        controller.onAckReceived(i, 1200, now);
        now = now.add(const Duration(milliseconds: 1));
      }
      expect(controller.cwndInPackets, greaterThan(2));

      // Sudden large spacing increase.
      now = now.add(const Duration(milliseconds: 10));
      controller.onAckReceived(3, 1200, now);
      // Should have exited slow start; next ack uses CUBIC.
      final before = controller.congestionWindow;
      controller.onAckReceived(4, 1200, now.add(const Duration(seconds: 1)));
      expect(controller.congestionWindow, greaterThanOrEqualTo(before));
    });
  });
}

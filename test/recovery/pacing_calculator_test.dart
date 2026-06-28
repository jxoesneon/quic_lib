import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/pacing_calculator.dart';

void main() {
  group('PacingCalculator', () {
    late PacingCalculator calculator;

    setUp(() {
      calculator = PacingCalculator();
    });

    test('default pacing interval calculation', () {
      // Default: smoothedRttUs = 333000, cwnd = 2400, packetSize = 1200
      // pacingIntervalUs = packetSize * smoothedRttUs / cwnd
      //                  = 1200 * 333000 / 2400 = 166500
      expect(calculator.pacingIntervalUs, equals(166500));

      // pacingRate = cwnd / smoothedRttUs = 2400 / 333000
      expect(calculator.pacingRate, closeTo(2400.0 / 333000.0, 1e-9));
    });

    test('larger cwnd reduces interval', () {
      final smallCwndInterval = calculator.pacingIntervalUs;

      calculator.updateCongestionWindow(4800);
      final largeCwndInterval = calculator.pacingIntervalUs;

      // Interval should be halved when cwnd is doubled.
      expect(largeCwndInterval, equals(smallCwndInterval ~/ 2));
      expect(largeCwndInterval, lessThan(smallCwndInterval));
    });

    test('shouldPace true when cwnd > 2*packet_size', () {
      // Default cwnd = 2400, 2*packetSize = 2400 -> false
      expect(calculator.shouldPace, isFalse);

      calculator.updateCongestionWindow(2401);
      expect(calculator.shouldPace, isTrue);

      calculator.updateCongestionWindow(5000);
      expect(calculator.shouldPace, isTrue);
    });

    test('updateRtt changes interval', () {
      final originalInterval = calculator.pacingIntervalUs;

      // Halve the RTT; interval should also halve.
      calculator.updateRtt(166500);
      final newInterval = calculator.pacingIntervalUs;

      expect(newInterval, equals(originalInterval ~/ 2));
      expect(newInterval, lessThan(originalInterval));
    });

    test('reset restores defaults', () {
      calculator.updateRtt(100000);
      calculator.updateCongestionWindow(10000);

      expect(calculator.pacingIntervalUs, isNot(equals(166500)));
      expect(calculator.shouldPace, isTrue);

      calculator.reset();

      expect(calculator.pacingIntervalUs, equals(166500));
      expect(calculator.shouldPace, isFalse);
      expect(calculator.pacingRate, closeTo(2400.0 / 333000.0, 1e-9));
    });
  });
}

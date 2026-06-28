import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';

void main() {
  group('RttEstimator', () {
    late RttEstimator estimator;

    setUp(() {
      estimator = RttEstimator();
    });

    test('initial values match RFC defaults', () {
      expect(estimator.smoothedRtt, equals(333000));
      expect(estimator.rttVar, equals(166500));
      expect(estimator.minRtt, equals(333000));
      expect(estimator.latestRtt, equals(333000));
      expect(estimator.maxAckDelay, equals(25000));
    });

    test('first sample sets smoothed_rtt and rttvar correctly', () {
      estimator.update(100000);

      expect(estimator.smoothedRtt, equals(100000));
      expect(estimator.rttVar, equals(50000));
      expect(estimator.minRtt, equals(100000));
      expect(estimator.latestRtt, equals(100000));
    });

    test('subsequent samples use EWMA correctly', () {
      // First sample.
      estimator.update(100000);
      expect(estimator.smoothedRtt, equals(100000));
      expect(estimator.rttVar, equals(50000));
      expect(estimator.minRtt, equals(100000));

      // Second sample: 200000, no ack delay.
      estimator.update(200000, ackDelay: 0);
      // adjusted_rtt = 200000 - 0 = 200000
      // rttvar = (3*50000 + |100000 - 200000|) / 4 = (150000 + 100000) / 4 = 62500
      // smoothed = (7*100000 + 200000) / 8 = (700000 + 200000) / 8 = 112500
      expect(estimator.minRtt, equals(100000));
      expect(estimator.rttVar, equals(62500));
      expect(estimator.smoothedRtt, equals(112500));
      expect(estimator.latestRtt, equals(200000));

      // Third sample: 120000, ackDelay 10000.
      // ack_delay_used = min(10000, 25000) = 10000
      // 120000 - 100000 >= 10000 => adjusted = 110000
      estimator.update(120000, ackDelay: 10000);
      // rttvar = (3*62500 + |112500 - 110000|) / 4 = (187500 + 2500) / 4 = 47500
      // smoothed = (7*112500 + 110000) / 8 = (787500 + 110000) / 8 = 112187
      expect(estimator.minRtt, equals(100000));
      expect(estimator.rttVar, equals(47500));
      expect(estimator.smoothedRtt, equals(112187));
      expect(estimator.latestRtt, equals(120000));
    });

    test('min_rtt never increases', () {
      estimator.update(150000);
      expect(estimator.minRtt, equals(150000));

      estimator.update(200000);
      expect(estimator.minRtt, equals(150000));

      estimator.update(180000);
      expect(estimator.minRtt, equals(150000));

      estimator.update(100000);
      expect(estimator.minRtt, equals(100000));
    });

    test('ack_delay is not subtracted when sample equals min_rtt', () {
      // First sample establishes min_rtt.
      estimator.update(100000);
      expect(estimator.minRtt, equals(100000));
      expect(estimator.smoothedRtt, equals(100000));
      expect(estimator.rttVar, equals(50000));

      // Second sample equals min_rtt with ack_delay.
      // latest_rtt - min_rtt = 0 < ack_delay (5000), so adjusted = latest_rtt.
      estimator.update(100000, ackDelay: 5000);
      expect(estimator.minRtt, equals(100000));
      // rttvar = (3*50000 + |100000 - 100000|) / 4 = 37500
      expect(estimator.rttVar, equals(37500));
      // smoothed = (7*100000 + 100000) / 8 = 100000
      expect(estimator.smoothedRtt, equals(100000));
    });

    test('PTO duration formula correctness', () {
      // Test with initial values.
      // pto = 333000 + max(4*166500, 1000) + 25000
      //     = 333000 + 666000 + 25000 = 1024000
      expect(estimator.getPtoDuration(), equals(1024000));

      // After first sample.
      estimator.update(100000);
      // pto = 100000 + max(4*50000, 1000) + 25000
      //     = 100000 + 200000 + 25000 = 325000
      expect(estimator.getPtoDuration(), equals(325000));

      // After second sample (from EWMA test above).
      estimator.update(200000, ackDelay: 0);
      // smoothed = 112500, rttvar = 62500
      // pto = 112500 + max(4*62500, 1000) + 25000
      //     = 112500 + 250000 + 25000 = 387500
      expect(estimator.getPtoDuration(), equals(387500));

      // With max_ack_delay set to 0 (Initial/Handshake space).
      estimator.maxAckDelay = 0;
      expect(
        estimator.getPtoDuration(),
        equals(112500 + 250000 + 0), // 362500
      );
    });

    test('reset() restores initial values', () {
      estimator.update(100000);
      estimator.update(200000, ackDelay: 5000);
      estimator.maxAckDelay = 0;

      estimator.reset();

      expect(estimator.smoothedRtt, equals(333000));
      expect(estimator.rttVar, equals(166500));
      expect(estimator.minRtt, equals(333000));
      expect(estimator.latestRtt, equals(333000));
      expect(estimator.maxAckDelay, equals(25000));
    });
  });
}

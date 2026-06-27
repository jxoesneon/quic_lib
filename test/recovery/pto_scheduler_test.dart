import 'package:test/test.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';

void main() {
  group('PtoScheduler', () {
    late RttEstimator rttEstimator;
    late PtoScheduler scheduler;

    setUp(() {
      rttEstimator = RttEstimator();
      scheduler = PtoScheduler(rttEstimator);
    });

    test('initial PTO matches rttEstimator.getPtoDuration()', () {
      expect(scheduler.currentPtoUs, equals(rttEstimator.getPtoDuration()));
      expect(scheduler.ptoCount, equals(0));
    });

    test('after firing, PTO doubles', () {
      final basePto = scheduler.currentPtoUs;
      scheduler.onPtoFired(1000);
      expect(scheduler.ptoCount, equals(1));
      expect(scheduler.currentPtoUs, equals(basePto * 2));
    });

    test('after ACK, PTO resets', () {
      scheduler.onPtoFired(1000);
      expect(scheduler.ptoCount, equals(1));
      scheduler.onAckReceived();
      expect(scheduler.ptoCount, equals(0));
      expect(scheduler.currentPtoUs, equals(rttEstimator.getPtoDuration()));
    });

    test('isExpired returns true when time exceeded', () {
      const now = 1000000;
      scheduler.onPtoFired(now);
      final ptoDuration = scheduler.currentPtoUs;
      expect(scheduler.isExpired(now + ptoDuration - 1), isFalse);
      expect(scheduler.isExpired(now + ptoDuration), isTrue);
      expect(scheduler.isExpired(now + ptoDuration + 1), isTrue);
    });

    test('reset() clears state', () {
      scheduler.onPtoFired(1000);
      expect(scheduler.ptoCount, equals(1));
      expect(scheduler.isExpired(1000 + scheduler.currentPtoUs), isTrue);

      scheduler.reset();

      expect(scheduler.ptoCount, equals(0));
      expect(scheduler.currentPtoUs, equals(rttEstimator.getPtoDuration()));
      expect(scheduler.isExpired(999999999), isFalse);
    });
  });
}

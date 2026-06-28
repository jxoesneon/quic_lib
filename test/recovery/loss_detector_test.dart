import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';

void main() {
  group('LossDetector', () {
    test('packet threshold at exactly gap = 3', () {
      final ld = LossDetector();
      expect(ld.isPacketLostByThreshold(0, 3), isTrue);
    });

    test('packet threshold below gap = 3 returns false', () {
      final ld = LossDetector();
      expect(ld.isPacketLostByThreshold(1, 3), isFalse);
    });

    test('time threshold fires correctly', () {
      final ld = LossDetector();
      final sentTime = 0;
      final ackTime = 100000; // 100ms
      final srtt = 10000; // 10ms
      final threshold =
          ((LossDetector.timeThreshold * srtt) + LossDetector.kGranularity)
              .toInt();
      expect(ld.isPacketLostByTime(0, sentTime, ackTime, srtt), isTrue);
      expect(ld.isPacketLostByTime(0, ackTime - threshold + 1, ackTime, srtt),
          isFalse);
    });

    test('ACK processing returns correct lost packets', () {
      final ld = LossDetector();
      final now = 1000000;
      ld.onPacketSent(0, now - 200000);
      ld.onPacketSent(1, now - 200000);
      ld.onPacketSent(2, now - 200000);
      ld.onPacketSent(3, now - 200000);
      ld.onPacketSent(4, now - 200000);
      // ACK packets 0 and 1 only; packets 2, 3, 4 should be declared lost
      final lost = ld.onAckReceived(1, now, 10000);
      expect(lost, contains(4));
      expect(lost, contains(3));
      expect(lost, contains(2));
    });

    test('reset clears state', () {
      final ld = LossDetector();
      ld.onPacketSent(0, 0);
      ld.reset();
      expect(ld.largestAcked, equals(-1));
    });
  });
}

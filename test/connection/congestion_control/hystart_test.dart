import 'package:test/test.dart';
import 'package:quic_lib/src/connection/congestion_control/hystart.dart';

void main() {
  group('Hystart', () {
    late Hystart hystart;

    setUp(() {
      hystart = Hystart();
    });

    test('initial state does not signal exit', () {
      expect(hystart.shouldExitSlowStart, isFalse);
    });

    test('reset clears exit state', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      for (var i = 0; i < 10; i++) {
        hystart.onAck(i, now);
        now = now.add(const Duration(milliseconds: 1));
      }
      expect(hystart.shouldExitSlowStart, isTrue);
      hystart.reset();
      expect(hystart.shouldExitSlowStart, isFalse);
    });

    test('ack train length threshold triggers exit', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      // 8 consecutive ACKs < 2ms apart should trigger exit.
      for (var i = 0; i < 8; i++) {
        expect(hystart.shouldExitSlowStart, isFalse);
        hystart.onAck(i, now);
        now = now.add(const Duration(milliseconds: 1));
      }
      expect(hystart.shouldExitSlowStart, isTrue);
    });

    test('gap in ack train resets count', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      // 5 ACKs with small gaps.
      for (var i = 0; i < 5; i++) {
        hystart.onAck(i, now);
        now = now.add(const Duration(milliseconds: 1));
      }
      expect(hystart.shouldExitSlowStart, isFalse);

      // Gap of 1ms from the last ack (now is already 1ms ahead because
      // we increment after each onAck). Total gap = 2ms, which resets the
      // train without triggering delay-based exit (2ms is not > 2*1ms).
      now = now.add(const Duration(milliseconds: 1));
      hystart.onAck(5, now);
      expect(hystart.shouldExitSlowStart, isFalse);

      // Need another 8 ACKs after reset.
      for (var i = 6; i < 14; i++) {
        now = now.add(const Duration(milliseconds: 1));
        hystart.onAck(i, now);
      }
      expect(hystart.shouldExitSlowStart, isTrue);
    });

    test('delay-based exit on ack spacing doubling', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      // Establish a baseline spacing of 1ms.
      hystart.onAck(0, now);
      now = now.add(const Duration(milliseconds: 1));
      hystart.onAck(1, now);
      now = now.add(const Duration(milliseconds: 1));
      hystart.onAck(2, now);
      expect(hystart.shouldExitSlowStart, isFalse);

      // Next spacing is > 2x previous (1ms -> 3ms).
      now = now.add(const Duration(milliseconds: 3));
      hystart.onAck(3, now);
      expect(hystart.shouldExitSlowStart, isTrue);
    });

    test('no exit for moderate spacing increase', () {
      var now = DateTime(2024, 1, 1, 0, 0, 0);
      hystart.onAck(0, now);
      now = now.add(const Duration(milliseconds: 2));
      hystart.onAck(1, now);
      now = now.add(const Duration(milliseconds: 3));
      // Spacing went from 2ms to 3ms (1.5x), not enough to trigger.
      hystart.onAck(2, now);
      expect(hystart.shouldExitSlowStart, isFalse);
    });
  });
}

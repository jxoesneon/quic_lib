import 'package:quic_lib/src/recovery/pacing_timer.dart';
import 'package:test/test.dart';

void main() {
  group('PacingTimer', () {
    test('returns 0 when pacing interval is 0 or negative', () {
      var now = 0;
      final timer = PacingTimer(clockUs: () => now);
      expect(timer.timeUntilNextSend(0), equals(0));
      expect(timer.timeUntilNextSend(-5), equals(0));
    });

    test('allows immediate first send and records the time', () {
      var now = 1000;
      final timer = PacingTimer(clockUs: () => now);
      expect(timer.timeUntilNextSend(100), equals(0));

      // Subsequent sends within the interval are delayed.
      now += 50;
      expect(timer.timeUntilNextSend(100), equals(50));
    });

    test('returns remaining delay when interval has not elapsed', () {
      var now = 1000;
      final timer = PacingTimer(clockUs: () => now);
      timer.recordSend();
      now += 50;
      expect(timer.timeUntilNextSend(200), equals(150));
    });

    test('returns 0 after the full interval has elapsed', () {
      var now = 1000;
      final timer = PacingTimer(clockUs: () => now);
      timer.recordSend();
      now += 300;
      expect(timer.timeUntilNextSend(200), equals(0));
    });

    test('multiple consecutive sends respect the interval', () {
      var now = 0;
      final timer = PacingTimer(clockUs: () => now);

      // First send is immediate and records the time.
      expect(timer.timeUntilNextSend(100), equals(0));

      now += 40;
      expect(timer.timeUntilNextSend(100), equals(60));

      now += 60;
      expect(timer.timeUntilNextSend(100), equals(0));

      now += 10;
      expect(timer.timeUntilNextSend(100), equals(90));
    });
  });
}

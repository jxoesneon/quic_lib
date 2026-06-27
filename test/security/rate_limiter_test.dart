import 'package:test/test.dart';
import 'package:dart_quic/src/security/rate_limiter.dart';

void main() {
  group('RateLimiter', () {
    test('allows calls within limit', () {
      final limiter = RateLimiter(maxCalls: 3, windowMs: 1000);
      expect(limiter.check(0), isTrue);
      expect(limiter.check(100), isTrue);
      expect(limiter.check(200), isTrue);
      expect(limiter.currentCount, equals(3));
    });

    test('rejects calls beyond limit', () {
      final limiter = RateLimiter(maxCalls: 2, windowMs: 1000);
      expect(limiter.check(0), isTrue);
      expect(limiter.check(100), isTrue);
      expect(limiter.check(200), isFalse);
      expect(limiter.currentCount, equals(2));
    });

    test('prunes old entries after window expires', () {
      final limiter = RateLimiter(maxCalls: 2, windowMs: 1000);
      expect(limiter.check(0), isTrue);
      expect(limiter.check(100), isTrue);
      expect(limiter.check(1100), isTrue); // First call pruned
      expect(limiter.currentCount, equals(2));
    });

    test('checkOrThrow throws on rejection', () {
      final limiter = RateLimiter(maxCalls: 1, windowMs: 1000);
      limiter.checkOrThrow(0);
      expect(() => limiter.checkOrThrow(100), throwsA(isA<StateError>()));
    });

    test('checkOrThrow without label uses generic message', () {
      final limiter = RateLimiter(maxCalls: 1, windowMs: 1000);
      limiter.checkOrThrow(0);
      expect(
        () => limiter.checkOrThrow(100),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            contains('Rate limit exceeded (1/1000 ms)'),
          ),
        ),
      );
    });

    test('reset clears all state', () {
      final limiter = RateLimiter(maxCalls: 2, windowMs: 1000);
      limiter.check(0);
      limiter.check(100);
      limiter.reset();
      expect(limiter.currentCount, equals(0));
      expect(limiter.check(200), isTrue);
    });
  });
}

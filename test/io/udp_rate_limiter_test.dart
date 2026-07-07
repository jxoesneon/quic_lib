import 'dart:io';

import 'package:quic_lib/src/io/udp_rate_limiter.dart';
import 'package:test/test.dart';

void main() {
  group('UdpRateLimiter', () {
    test('allows packets within the per-source limit', () {
      final limiter = UdpRateLimiter();
      final address = InternetAddress('10.0.0.1');

      for (var i = 0; i < 1000; i++) {
        expect(limiter.isAllowed(address), isTrue);
      }
    });

    test('drops packets that exceed the per-source limit', () {
      final limiter = UdpRateLimiter();
      final address = InternetAddress('10.0.0.1');

      for (var i = 0; i < 1000; i++) {
        expect(limiter.isAllowed(address), isTrue);
      }
      expect(limiter.isAllowed(address), isFalse);
    });

    test('tracks each source IP independently', () {
      final limiter = UdpRateLimiter();
      final addressA = InternetAddress('10.0.0.1');
      final addressB = InternetAddress('10.0.0.2');

      for (var i = 0; i < 1000; i++) {
        expect(limiter.isAllowed(addressA), isTrue);
        expect(limiter.isAllowed(addressB), isTrue);
      }
      expect(limiter.isAllowed(addressA), isFalse);
      expect(limiter.isAllowed(addressB), isFalse);
    });

    test('resets the allowance after the rate-limit window passes', () async {
      final limiter = UdpRateLimiter();
      final address = InternetAddress('10.0.0.1');

      for (var i = 0; i < 1000; i++) {
        expect(limiter.isAllowed(address), isTrue);
      }
      expect(limiter.isAllowed(address), isFalse);

      await Future.delayed(Duration(milliseconds: 1100));

      expect(limiter.isAllowed(address), isTrue);
    });

    test('prunes timestamps that fall outside the window', () {
      var now = 1000000;
      final limiter = UdpRateLimiter(clock: () => now);
      final address = InternetAddress('10.0.0.1');

      // Saturate the per-source limit.
      for (var i = 0; i < 1000; i++) {
        expect(limiter.isAllowed(address), isTrue);
      }
      expect(limiter.isAllowed(address), isFalse);

      // Advance past the window so old timestamps are pruned.
      now += 1100;
      expect(limiter.isAllowed(address), isTrue);
    });

    test('evicts the oldest tracked source when a new IP arrives at capacity',
        () {
      var now = 10000;
      final limiter = UdpRateLimiter(clock: () => now);
      final oldest = InternetAddress('10.0.0.1');
      final middle = InternetAddress('10.0.0.2');
      final newest = InternetAddress('10.0.0.3');

      // Saturate three sources at distinct times.
      for (var i = 0; i < 1000; i++) {
        now = 10000;
        expect(limiter.isAllowed(oldest), isTrue);
      }
      for (var i = 0; i < 1000; i++) {
        now = 10001;
        expect(limiter.isAllowed(middle), isTrue);
      }
      for (var i = 0; i < 1000; i++) {
        now = 10002;
        expect(limiter.isAllowed(newest), isTrue);
      }

      // Fill the remainder of the table so it reaches capacity.
      for (var i = 0; i < 9997; i++) {
        final a = (i >> 8) & 0xFF;
        final b = i & 0xFF;
        expect(
          limiter.isAllowed(InternetAddress('0.0.$a.$b')),
          isTrue,
        );
      }

      // A new source should trigger eviction of the oldest entry.
      now = 10002;
      expect(
        limiter.isAllowed(InternetAddress('192.168.0.1')),
        isTrue,
      );

      // Middle and newest are still tracked and remain at capacity; oldest was
      // evicted and therefore starts fresh.
      now = 10002;
      expect(limiter.isAllowed(middle), isFalse);
      expect(limiter.isAllowed(newest), isFalse);
      expect(limiter.isAllowed(oldest), isTrue);
    });

    test(
        'does not evict when a packet arrives from an already-tracked source '
        'while at capacity', () {
      var now = 10000;
      final limiter = UdpRateLimiter(clock: () => now);
      final tracked = InternetAddress('10.0.0.1');

      // Saturate the tracked source.
      for (var i = 0; i < 1000; i++) {
        now = 10000;
        expect(limiter.isAllowed(tracked), isTrue);
      }

      // Fill the remainder of the table.
      for (var i = 0; i < 9999; i++) {
        final a = (i >> 8) & 0xFF;
        final b = i & 0xFF;
        expect(
          limiter.isAllowed(InternetAddress('0.0.$a.$b')),
          isTrue,
        );
      }

      // Receiving from the already-tracked source must not evict it, so it
      // remains at capacity and the datagram is dropped.
      now = 10001;
      expect(limiter.isAllowed(tracked), isFalse);
    });
  });
}

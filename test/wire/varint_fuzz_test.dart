import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';
import 'package:test/test.dart';

/// Fuzzing/error-path tests for [VarInt].
///
/// Feeds malformed, truncated, and random bytes to the decoder and verifies that
/// it either returns a valid non-negative value within range or throws an
/// [ArgumentError] -- never silently returns a wrong result or crashes with an
/// unexpected exception type.
void main() {
  group('VarInt decode fuzz/error tests', () {
    test('decode throws ArgumentError for every truncated length flag', () {
      for (var flag = 0; flag < 4; flag++) {
        final base = flag << 6;
        final length = 1 << flag;
        for (var given = 1; given < length; given++) {
          final buffer = Uint8List.fromList(
            List.generate(given, (i) => i == 0 ? base | 0x01 : 0x00),
          ).buffer;
          expect(
            () => VarInt.decode(buffer),
            throwsArgumentError,
            reason: 'flag=$flag, length=$length, given=$given',
          );
        }
      }
    });

    test('decode returns a valid in-range value or throws ArgumentError', () {
      final random = Random(42);
      for (var i = 0; i < 1000; i++) {
        final len = random.nextInt(32) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        try {
          final value = VarInt.decode(bytes.buffer);
          expect(value, greaterThanOrEqualTo(0));
          expect(value, lessThanOrEqualTo(VarInt.maxValue));
        } on ArgumentError catch (_) {
          // Expected failure mode.
        }
      }
    });

    test('decode rejects negative offset and offsets beyond buffer', () {
      final buffer = Uint8List.fromList([0x25]).buffer;
      expect(() => VarInt.decode(buffer, offset: -1), throwsArgumentError);
      expect(() => VarInt.decode(buffer, offset: 1), throwsArgumentError);
      expect(
        () => VarInt.decode(buffer, offset: 1000),
        throwsArgumentError,
      );
    });

    test('decode rejects the maximum length flag with too few bytes', () {
      // 8-byte flag with only 7 bytes.
      final buffer = Uint8List.fromList(
        [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
      ).buffer;
      expect(() => VarInt.decode(buffer), throwsArgumentError);
    });

    test('decodeLength handles all 2MSB flags', () {
      expect(VarInt.decodeLength(0x00), 1);
      expect(VarInt.decodeLength(0x40), 2);
      expect(VarInt.decodeLength(0x80), 4);
      expect(VarInt.decodeLength(0xC0), 8);
    });
  });

  group('VarInt encode fuzz/error tests', () {
    test('encode throws for negative values', () {
      expect(() => VarInt.encode(-1), throwsArgumentError);
      expect(
          () => VarInt.encode(-Random().nextInt(1 << 62)), throwsArgumentError);
    });

    test('encode throws for values above the 62-bit maximum', () {
      expect(() => VarInt.encode(VarInt.maxValue + 1), throwsArgumentError);
      expect(
        () => VarInt.encode(0xFFFFFFFFFFFFFFFF),
        throwsArgumentError,
      );
    });

    test('random round-trips stay within range', () {
      final random = Random(123);
      for (var i = 0; i < 500; i++) {
        final high = random.nextInt(1 << 31);
        final low = random.nextInt(1 << 31);
        var value = (high << 31) | low;
        if (value > VarInt.maxValue) {
          expect(() => VarInt.encode(value), throwsArgumentError);
          continue;
        }
        final encoded = VarInt.encode(value);
        final decoded = VarInt.decode(encoded.buffer);
        expect(decoded, equals(value));
      }
    });
  });
}

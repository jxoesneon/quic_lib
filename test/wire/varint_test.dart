import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/wire/varint.dart';

import '../helpers/hex.dart';

void main() {
  group('VarInt', () {
    group('encode', () {
      test('encodes 0 as 1 byte', () {
        expect(VarInt.encode(0), equals(hexDecode('00')));
      });

      test('encodes 1 as 1 byte', () {
        expect(VarInt.encode(1), equals(hexDecode('01')));
      });

      test('encodes 63 as 1 byte', () {
        expect(VarInt.encode(63), equals(hexDecode('3f')));
      });

      test('encodes 64 as 2 bytes', () {
        expect(VarInt.encode(64), equals(hexDecode('4040')));
      });

      test('encodes 16383 as 2 bytes', () {
        expect(VarInt.encode(16383), equals(hexDecode('7fff')));
      });

      test('encodes 16384 as 4 bytes', () {
        expect(VarInt.encode(16384), equals(hexDecode('80004000')));
      });

      test('encodes 1073741823 as 4 bytes', () {
        expect(VarInt.encode(1073741823), equals(hexDecode('bfffffff')));
      });

      test('encodes 1073741824 as 8 bytes', () {
        expect(
          VarInt.encode(1073741824),
          equals(hexDecode('c000000040000000')),
        );
      });

      test('encodes max value as 8 bytes', () {
        expect(
          VarInt.encode(4611686018427387903),
          equals(hexDecode('ffffffffffffffff')),
        );
      });

      test('throws ArgumentError for negative values', () {
        expect(() => VarInt.encode(-1), throwsArgumentError);
      });

      test('throws ArgumentError for values > maxValue', () {
        expect(
          () => VarInt.encode(4611686018427387904),
          throwsArgumentError,
        );
      });
    });

    group('decode', () {
      test('decodes 1-byte varint', () {
        final buffer = Uint8List.fromList(hexDecode('00')).buffer;
        expect(VarInt.decode(buffer), equals(0));
      });

      test('decodes 2-byte varint', () {
        final buffer = Uint8List.fromList(hexDecode('4040')).buffer;
        expect(VarInt.decode(buffer), equals(64));
      });

      test('decodes 4-byte varint', () {
        final buffer = Uint8List.fromList(hexDecode('80004000')).buffer;
        expect(VarInt.decode(buffer), equals(16384));
      });

      test('decodes 8-byte varint', () {
        final buffer = Uint8List.fromList(
          hexDecode('c000000040000000'),
        ).buffer;
        expect(VarInt.decode(buffer), equals(1073741824));
      });

      test('decodes max value', () {
        final buffer = Uint8List.fromList(
          hexDecode('ffffffffffffffff'),
        ).buffer;
        expect(VarInt.decode(buffer), equals(4611686018427387903));
      });

      test('decodes RFC test vector: 37 → 0x25', () {
        final buffer = Uint8List.fromList(hexDecode('25')).buffer;
        expect(VarInt.decode(buffer), equals(37));
      });

      test('decodes RFC test vector: 15,293 → 0x7bbd', () {
        final buffer = Uint8List.fromList(hexDecode('7bbd')).buffer;
        expect(VarInt.decode(buffer), equals(15293));
      });

      test('decodes RFC test vector: 494,878,333 → 0x9d7f3e7d', () {
        final buffer = Uint8List.fromList(hexDecode('9d7f3e7d')).buffer;
        expect(VarInt.decode(buffer), equals(494878333));
      });

      test(
        'decodes RFC test vector: 151,288,809,941,952,652 → 0xc2197c5eff14e88c',
        () {
          final buffer = Uint8List.fromList(
            hexDecode('c2197c5eff14e88c'),
          ).buffer;
          expect(VarInt.decode(buffer), equals(151288809941952652));
        },
      );

      test('decodes non-minimal encoding (37 as 2 bytes)', () {
        final buffer = Uint8List.fromList(hexDecode('4025')).buffer;
        expect(VarInt.decode(buffer), equals(37));
      });

      test('decodes with non-zero offset', () {
        final bytes = Uint8List.fromList(hexDecode('00 7fff'));
        expect(VarInt.decode(bytes.buffer, offset: 1), equals(16383));
      });

      test('throws ArgumentError for empty buffer', () {
        final buffer = Uint8List(0).buffer;
        expect(() => VarInt.decode(buffer), throwsArgumentError);
      });

      test('throws ArgumentError for truncated 2-byte varint', () {
        final buffer = Uint8List.fromList([0x40]).buffer;
        expect(() => VarInt.decode(buffer), throwsArgumentError);
      });

      test('throws ArgumentError for truncated 4-byte varint', () {
        final buffer = Uint8List.fromList([0x80, 0x00, 0x00]).buffer;
        expect(() => VarInt.decode(buffer), throwsArgumentError);
      });

      test('throws ArgumentError for truncated 8-byte varint', () {
        final buffer = Uint8List.fromList(
          [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ).buffer;
        expect(() => VarInt.decode(buffer), throwsArgumentError);
      });

      test('throws ArgumentError for negative offset', () {
        final buffer = Uint8List.fromList([0x00]).buffer;
        expect(() => VarInt.decode(buffer, offset: -1), throwsArgumentError);
      });

      test('throws ArgumentError for offset at end of buffer', () {
        final buffer = Uint8List.fromList([0x00]).buffer;
        expect(() => VarInt.decode(buffer, offset: 1), throwsArgumentError);
      });
    });

    group('decodeLength', () {
      test('returns 1 for 2MSB = 00', () {
        expect(VarInt.decodeLength(0x00), equals(1));
        expect(VarInt.decodeLength(0x3F), equals(1));
      });

      test('returns 2 for 2MSB = 01', () {
        expect(VarInt.decodeLength(0x40), equals(2));
        expect(VarInt.decodeLength(0x7F), equals(2));
      });

      test('returns 4 for 2MSB = 10', () {
        expect(VarInt.decodeLength(0x80), equals(4));
        expect(VarInt.decodeLength(0xBF), equals(4));
      });

      test('returns 8 for 2MSB = 11', () {
        expect(VarInt.decodeLength(0xC0), equals(8));
        expect(VarInt.decodeLength(0xFF), equals(8));
      });
    });

    group('round-trip', () {
      final random = Random(42);

      test('round-trips random 1-byte values', () {
        for (var i = 0; i < 100; i++) {
          final value = random.nextInt(64);
          final encoded = VarInt.encode(value);
          final decoded = VarInt.decode(encoded.buffer);
          expect(decoded, equals(value));
        }
      });

      test('round-trips random 2-byte values', () {
        for (var i = 0; i < 100; i++) {
          final value = 64 + random.nextInt(16384 - 64);
          final encoded = VarInt.encode(value);
          final decoded = VarInt.decode(encoded.buffer);
          expect(decoded, equals(value));
        }
      });

      test('round-trips random 4-byte values', () {
        for (var i = 0; i < 100; i++) {
          final value = 16384 + random.nextInt(1073741824 - 16384);
          final encoded = VarInt.encode(value);
          final decoded = VarInt.decode(encoded.buffer);
          expect(decoded, equals(value));
        }
      });

      test('round-trips random 8-byte values', () {
        for (var i = 0; i < 100; i++) {
          // Construct random 62-bit value using two 31-bit halves
          final high = random.nextInt(1 << 31);
          final low = random.nextInt(1 << 31);
          final value = (high << 31) | low;
          // Ensure it's in the 8-byte range and <= maxValue
          if (value < 1073741824) continue;
          if (value > VarInt.maxValue) continue;
          final encoded = VarInt.encode(value);
          final decoded = VarInt.decode(encoded.buffer);
          expect(decoded, equals(value),
              reason: 'Failed for value $value');
        }
      });
    });

    group('maxValue', () {
      test('returns 4611686018427387903', () {
        expect(VarInt.maxValue, equals(4611686018427387903));
      });
    });
  });
}

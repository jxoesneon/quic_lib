import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_integer.dart';
import 'package:test/test.dart';

void main() {
  group('QpackInteger.encode', () {
    test('small values fit in one byte with prefixBits=5', () {
      expect(QpackInteger.encode(0, 5), equals(Uint8List.fromList([0x00])));
      expect(QpackInteger.encode(10, 5), equals(Uint8List.fromList([0x0A])));
      expect(
        QpackInteger.encode(30, 5),
        equals(Uint8List.fromList([0x1E])),
      );
    });

    test('value exactly at prefix limit requires continuation', () {
      // prefixBits=5 → limit=31. 31 needs one continuation byte (0).
      expect(
        QpackInteger.encode(31, 5),
        equals(Uint8List.fromList([0x1F, 0x00])),
      );
    });

    test('large values produce multiple continuation bytes', () {
      // RFC 7541 example: 1337 with 5-bit prefix → 0x1F 0x9A 0x0A
      expect(
        QpackInteger.encode(1337, 5),
        equals(Uint8List.fromList([0x1F, 0x9A, 0x0A])),
      );

      // A moderately large value.
      // prefixBits=5, limit=31. remaining = 1000 - 31 = 969.
      // 969 = 128*7 + 73  → 73|0x80 = 0xC9, then 7.
      expect(
        QpackInteger.encode(1000, 5),
        equals(Uint8List.fromList([0x1F, 0xC9, 0x07])),
      );
    });

    test('different prefixBits work correctly', () {
      // prefixBits=1 → limit=1. 0 fits in one byte.
      expect(QpackInteger.encode(0, 1), equals(Uint8List.fromList([0x00])));

      // prefixBits=1 → value=1 needs continuation.
      expect(
          QpackInteger.encode(1, 1), equals(Uint8List.fromList([0x01, 0x00])));

      // prefixBits=1 → value=2.
      expect(
          QpackInteger.encode(2, 1), equals(Uint8List.fromList([0x01, 0x01])));

      // prefixBits=7 → limit=127. 126 in one byte.
      expect(QpackInteger.encode(126, 7), equals(Uint8List.fromList([0x7E])));

      // prefixBits=7 → 127 needs continuation.
      expect(
        QpackInteger.encode(127, 7),
        equals(Uint8List.fromList([0x7F, 0x00])),
      );

      // prefixBits=8 → limit=255. 254 in one byte.
      expect(QpackInteger.encode(254, 8), equals(Uint8List.fromList([0xFE])));

      // prefixBits=8 → 255 needs continuation.
      expect(
        QpackInteger.encode(255, 8),
        equals(Uint8List.fromList([0xFF, 0x00])),
      );
    });

    test('rejects invalid prefixBits', () {
      expect(() => QpackInteger.encode(0, 0), throwsArgumentError);
      expect(() => QpackInteger.encode(0, 9), throwsArgumentError);
    });

    test('rejects negative values', () {
      expect(() => QpackInteger.encode(-1, 5), throwsArgumentError);
    });
  });

  group('QpackInteger.decode', () {
    test('decodes small single-byte values', () {
      expect(QpackInteger.decode(Uint8List.fromList([0x00]), 0, 5),
          equals((0, 1)));
      expect(QpackInteger.decode(Uint8List.fromList([0x0A]), 0, 5),
          equals((10, 1)));
      expect(QpackInteger.decode(Uint8List.fromList([0x1E]), 0, 5),
          equals((30, 1)));
    });

    test('decodes continuation bytes', () {
      // 1337 example from RFC.
      expect(
        QpackInteger.decode(Uint8List.fromList([0x1F, 0x9A, 0x0A]), 0, 5),
        equals((1337, 3)),
      );
    });

    test('decodes with non-zero offset', () {
      final buffer = Uint8List.fromList([0xFF, 0x1F, 0x9A, 0x0A, 0x00]);
      expect(
        QpackInteger.decode(buffer, 1, 5),
        equals((1337, 4)),
      );
    });

    test('different prefixBits decode correctly', () {
      // prefixBits=1
      expect(
        QpackInteger.decode(Uint8List.fromList([0x01, 0x00]), 0, 1),
        equals((1, 2)),
      );

      // prefixBits=7
      expect(
        QpackInteger.decode(Uint8List.fromList([0x7F, 0x00]), 0, 7),
        equals((127, 2)),
      );

      // prefixBits=8
      expect(
        QpackInteger.decode(Uint8List.fromList([0xFF, 0x00]), 0, 8),
        equals((255, 2)),
      );
    });

    test('rejects invalid prefixBits', () {
      expect(
        () => QpackInteger.decode(Uint8List(1), 0, 0),
        throwsArgumentError,
      );
      expect(
        () => QpackInteger.decode(Uint8List(1), 0, 9),
        throwsArgumentError,
      );
    });

    test('rejects out of bounds offset', () {
      expect(
        () => QpackInteger.decode(Uint8List(1), -1, 5),
        throwsArgumentError,
      );
      expect(
        () => QpackInteger.decode(Uint8List(1), 1, 5),
        throwsArgumentError,
      );
    });

    test('rejects incomplete continuation', () {
      expect(
        () => QpackInteger.decode(Uint8List.fromList([0x1F, 0x9A]), 0, 5),
        throwsArgumentError,
      );
    });
  });

  group('QpackInteger round-trip', () {
    test('various values round-trip with prefixBits=5', () {
      final values = [0, 1, 30, 31, 32, 100, 1000, 1337, 100000];
      for (final v in values) {
        final encoded = QpackInteger.encode(v, 5);
        final (decoded, offset) = QpackInteger.decode(encoded, 0, 5);
        expect(decoded, equals(v), reason: 'value $v failed to round-trip');
        expect(offset, equals(encoded.length));
      }
    });

    test('various values round-trip with prefixBits=1', () {
      final values = [0, 1, 2, 10, 100, 1000];
      for (final v in values) {
        final encoded = QpackInteger.encode(v, 1);
        final (decoded, offset) = QpackInteger.decode(encoded, 0, 1);
        expect(decoded, equals(v), reason: 'value $v failed to round-trip');
        expect(offset, equals(encoded.length));
      }
    });

    test('various values round-trip with prefixBits=7', () {
      final values = [0, 126, 127, 128, 1000, 10000];
      for (final v in values) {
        final encoded = QpackInteger.encode(v, 7);
        final (decoded, offset) = QpackInteger.decode(encoded, 0, 7);
        expect(decoded, equals(v), reason: 'value $v failed to round-trip');
        expect(offset, equals(encoded.length));
      }
    });

    test('various values round-trip with prefixBits=8', () {
      final values = [0, 254, 255, 256, 1000, 100000];
      for (final v in values) {
        final encoded = QpackInteger.encode(v, 8);
        final (decoded, offset) = QpackInteger.decode(encoded, 0, 8);
        expect(decoded, equals(v), reason: 'value $v failed to round-trip');
        expect(offset, equals(encoded.length));
      }
    });
  });

  group('QpackInteger with instruction bits', () {
    test('caller can merge instruction bits into first byte', () {
      // Simulate an indexed header: top bit = 1, 7-bit index.
      final encoded = QpackInteger.encode(42, 7);
      expect(encoded[0], equals(42));

      // Merge instruction bit.
      final withInstruction =
          Uint8List.fromList([0x80 | encoded[0], ...encoded.skip(1)]);
      expect(withInstruction[0], equals(0x80 + 42));

      // Decode should mask off the instruction bit.
      final (decoded, offset) = QpackInteger.decode(withInstruction, 0, 7);
      expect(decoded, equals(42));
      expect(offset, equals(1));
    });
  });
}

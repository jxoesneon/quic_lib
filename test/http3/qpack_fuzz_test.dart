import 'dart:convert' show utf8;
import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_decoder.dart';
import 'package:quic_lib/src/http3/qpack_dynamic_table.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';
import 'package:quic_lib/src/http3/qpack_integer.dart';
import 'package:quic_lib/src/http3/qpack_static_table.dart';
import 'package:quic_lib/src/http3/qpack_string.dart';
import 'package:test/test.dart';

/// Fuzz/error-path tests for QPACK integers, strings, and the decoder/encoder.
///
/// Feeds malformed/truncated inputs and verifies that the code either throws
/// [ArgumentError] / [FormatException] or returns a sane result.
void main() {
  group('QpackInteger fuzz/error tests', () {
    test('decode rejects invalid prefixBits', () {
      final bytes = Uint8List.fromList([0x01]);
      expect(
        () => QpackInteger.decode(bytes, 0, 0),
        throwsArgumentError,
      );
      expect(
        () => QpackInteger.decode(bytes, 0, 9),
        throwsArgumentError,
      );
    });

    test('decode rejects out-of-bounds offset', () {
      final bytes = Uint8List.fromList([0x01]);
      expect(() => QpackInteger.decode(bytes, -1, 6), throwsArgumentError);
      expect(() => QpackInteger.decode(bytes, 1, 6), throwsArgumentError);
      expect(() => QpackInteger.decode(bytes, 100, 6), throwsArgumentError);
    });

    test('decode rejects truncated continuation', () {
      for (var prefixBits = 1; prefixBits <= 8; prefixBits++) {
        final prefixLimit = (1 << prefixBits) - 1;
        // First byte at the prefix limit, then a continuation byte that never ends.
        final bytes = Uint8List.fromList([prefixLimit, 0x80]);
        expect(
          () => QpackInteger.decode(bytes, 0, prefixBits),
          throwsArgumentError,
          reason: 'prefixBits=$prefixBits',
        );
      }
    });

    test('decode rejects overflow integers beyond 62 bits', () {
      // 6-bit prefix: prefixLimit = 63, then 9 continuation bytes; the final
      // byte produces a value greater than 2^62-1.
      final bytes = Uint8List.fromList([
        0x3F, // prefixLimit
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F,
      ]);
      expect(
        () => QpackInteger.decode(bytes, 0, 6),
        throwsArgumentError,
      );
    });

    test('decode returns sane results for random byte streams', () {
      final random = Random(42);
      for (var i = 0; i < 500; i++) {
        final len = random.nextInt(16) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        final prefixBits = random.nextInt(8) + 1;
        try {
          final (value, offset) = QpackInteger.decode(bytes, 0, prefixBits);
          expect(value, greaterThanOrEqualTo(0));
          expect(offset, greaterThan(0));
          expect(offset, lessThanOrEqualTo(bytes.length));
        } on ArgumentError catch (_) {
          // Expected.
        }
      }
    });

    test('encode rejects negative or oversized values', () {
      expect(() => QpackInteger.encode(-1, 6), throwsArgumentError);
      expect(
        () => QpackInteger.encode(QpackInteger.maxValue + 1, 6),
        throwsArgumentError,
      );
    });
  });

  group('QpackString fuzz/error tests', () {
    test('decode rejects truncated string literal', () {
      final encoded = QpackString.encode('hello');
      final truncated = encoded.sublist(0, encoded.length - 1);
      expect(
        () => QpackString.decode(truncated, 0),
        throwsArgumentError,
      );
    });

    test('decode rejects truncated string length encoding', () {
      // Huffman flag set, length prefix all ones, no continuation bytes.
      final bytes = Uint8List.fromList([0xFF]);
      expect(
        () => QpackString.decode(bytes, 0),
        throwsArgumentError,
      );
    });
  });

  group('QpackDecoder fuzz/error tests', () {
    test('decodeFieldLine throws for invalid prefix', () {
      final bytes = Uint8List.fromList([0x00]);
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for out-of-range static index', () {
      final index = QpackStaticTable.length + 100;
      final bytes = QpackInteger.encode(index, 6);
      bytes[0] |= 0x80; // indexed prefix
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for indexed static entry with null value', () {
      // Index 0 is ':authority' which has no value.
      final bytes = QpackInteger.encode(0, 6);
      bytes[0] |= 0x80;
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for literal name ref to out-of-range index',
        () {
      final index = QpackStaticTable.length + 100;
      final bytes = QpackInteger.encode(index, 5);
      bytes[0] |= 0x40; // literal with name ref prefix
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for truncated literal without name ref', () {
      // 001 prefix, then a string length of 1 but no payload bytes.
      final bytes = Uint8List.fromList([0x20, 0x01]);
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decode throws for post-base indexed with empty dynamic table', () {
      final bytes = QpackInteger.encode(0, 4);
      // prefix is already 0000, so no extra bits needed.
      expect(
        () => QpackDecoder().decode(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decode throws for post-base literal with empty dynamic table', () {
      final bytes = QpackInteger.encode(0, 4);
      bytes[0] |= 0x10; // 0001 prefix
      expect(
        () => QpackDecoder().decode(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeLines handles random garbage without unexpected crashes', () {
      final random = Random(123);
      final decoder = QpackDecoder();
      for (var i = 0; i < 200; i++) {
        final len = random.nextInt(32) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        try {
          decoder.decodeLines(bytes);
        } on ArgumentError catch (_) {
          // Expected malformed QPACK.
        } on FormatException catch (_) {
          // Expected invalid string encodings.
        }
      }
    });
  });

  group('QpackEncoder fuzz/error tests', () {
    test('encodeFieldLine produces valid encodings for arbitrary strings', () {
      final pairs = [
        (name: ':method', value: 'GET'),
        (name: 'x-very-long-header-name', value: 'a' * 1000),
        (name: 'binary', value: ''), // empty value
      ];
      for (final pair in pairs) {
        final bytes = QpackEncoder.encodeFieldLine(pair.name, pair.value);
        expect(bytes.isNotEmpty, isTrue);
        final (decoded, offset) = QpackDecoder.decodeFieldLine(bytes, 0);
        expect(decoded.name, equals(pair.name));
        expect(decoded.value, equals(pair.value));
        expect(offset, equals(bytes.length));
      }
    });

    test('dynamic table encoder with capacity stays consistent', () {
      final encoder = QpackEncoder();
      encoder.dynamicTable.setCapacity(1024);
      final bytes = encoder.encodeLines([
        (name: 'x-custom', value: 'value'),
        (name: 'x-custom', value: 'value2'),
      ]);
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(1024);
      // The decoder has no entries until it processes the encoder stream.
      // For this test we just verify the encoder does not crash.
      expect(bytes.isNotEmpty, isTrue);
      expect(encoder.emittedInstructions.length, greaterThan(0));
    });
  });
}

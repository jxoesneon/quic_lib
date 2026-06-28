import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_string.dart';
import 'package:test/test.dart';

void main() {
  group('QpackString round-trip', () {
    test('ASCII string', () {
      const value = 'Hello, World!';
      final encoded = QpackString.encode(value);
      final (decoded, offset) = QpackString.decode(encoded, 0);

      expect(decoded, equals(value));
      expect(offset, equals(encoded.length));
    });

    test('Unicode string', () {
      const value = 'Héllo, 世界! 🌍';
      final encoded = QpackString.encode(value);
      final (decoded, offset) = QpackString.decode(encoded, 0);

      expect(decoded, equals(value));
      expect(offset, equals(encoded.length));
    });

    test('long string uses multi-byte length', () {
      // 150 'A' characters → UTF-8 length = 150 (> 127).
      const value =
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      final encoded = QpackString.encode(value);

      // First byte should have prefix = 0x7F (127) because length >= 127.
      expect(encoded[0] & 0x7F, equals(0x7F));

      final (decoded, offset) = QpackString.decode(encoded, 0);
      expect(decoded, equals(value));
      expect(offset, equals(encoded.length));
    });

    test('empty string', () {
      const value = '';
      final encoded = QpackString.encode(value);
      final (decoded, offset) = QpackString.decode(encoded, 0);

      expect(decoded, equals(value));
      expect(offset, equals(encoded.length));
      expect(encoded, equals(Uint8List.fromList([0x00])));
    });

    test('decode with non-zero offset', () {
      const value = 'dart-quic';
      final encoded = QpackString.encode(value);
      final buffer = Uint8List.fromList([0xFF, 0xFE, ...encoded, 0x00]);

      final (decoded, offset) = QpackString.decode(buffer, 2);
      expect(decoded, equals(value));
      expect(offset, equals(2 + encoded.length));
    });
  });

  group('QpackString huffman flag', () {
    test('huffman flag is stored in first byte', () {
      const value = 'test';
      final encoded = QpackString.encode(value, huffman: true);

      // First byte should have bit 7 set.
      expect(encoded[0] & 0x80, equals(0x80));

      final (decoded, offset) = QpackString.decode(encoded, 0);
      expect(decoded, equals(value));
      expect(offset, equals(encoded.length));
    });

    test('huffman flag is clear when not requested', () {
      const value = 'test';
      final encoded = QpackString.encode(value, huffman: false);

      expect(encoded[0] & 0x80, equals(0x00));
    });
  });

  group('QpackString error handling', () {
    test('rejects negative offset', () {
      expect(
        () => QpackString.decode(Uint8List(1), -1),
        throwsArgumentError,
      );
    });

    test('rejects out of bounds offset', () {
      expect(
        () => QpackString.decode(Uint8List(1), 1),
        throwsArgumentError,
      );
    });

    test('rejects truncated string payload', () {
      // Encode a 4-byte string but drop the payload.
      final encoded = QpackString.encode('test');
      final truncated = Uint8List.fromList(encoded.sublist(0, 1));

      expect(
        () => QpackString.decode(truncated, 0),
        throwsArgumentError,
      );
    });

    test('rejects incomplete length continuation', () {
      // First byte indicates multi-byte length, but no continuation follows.
      final buffer = Uint8List.fromList([0x7F]);

      expect(
        () => QpackString.decode(buffer, 0),
        throwsArgumentError,
      );
    });
  });
}

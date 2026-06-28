import 'dart:typed_data';

import 'package:dart_quic/src/http3/qpack_decoder.dart';
import 'package:dart_quic/src/http3/qpack_encoder.dart';
import 'package:dart_quic/src/http3/qpack_integer.dart';
import 'package:test/test.dart';

void main() {
  group('QpackDecoder', () {
    test('decodeFieldLine round-trips indexed representation', () {
      final encoded = QpackEncoder.encodeFieldLine(':method', 'GET');
      final (decoded, offset) = QpackDecoder.decodeFieldLine(encoded, 0);
      expect(decoded.name, equals(':method'));
      expect(decoded.value, equals('GET'));
      expect(offset, equals(encoded.length));
    });

    test('decodeFieldLine round-trips literal with name reference', () {
      final encoded = QpackEncoder.encodeFieldLine(':status', '418');
      final (decoded, offset) = QpackDecoder.decodeFieldLine(encoded, 0);
      expect(decoded.name, equals(':status'));
      expect(decoded.value, equals('418'));
      expect(offset, equals(encoded.length));
    });

    test('decodeFieldLine round-trips literal without name reference', () {
      final encoded = QpackEncoder.encodeFieldLine('x-custom', 'value');
      final (decoded, offset) = QpackDecoder.decodeFieldLine(encoded, 0);
      expect(decoded.name, equals('x-custom'));
      expect(decoded.value, equals('value'));
      expect(offset, equals(encoded.length));
    });

    test('decodeFieldLines round-trips multiple lines', () {
      final lines = [
        (name: ':method', value: 'POST'),
        (name: ':authority', value: 'example.com'),
        (name: 'content-type', value: 'application/json'),
      ];
      final encoded = QpackEncoder.encodeFieldLines(lines);
      final decoded = QpackDecoder.decodeFieldLines(encoded);
      expect(decoded.length, equals(lines.length));
      for (var i = 0; i < lines.length; i++) {
        expect(decoded[i].name, equals(lines[i].name));
        expect(decoded[i].value, equals(lines[i].value));
      }
    });

    test('decodeFieldLine throws for unknown encoding', () {
      final bytes = Uint8List.fromList([0x00]); // invalid prefix
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for out-of-bounds static index', () {
      // Indexed representation with a very large index that doesn't exist.
      final bytes = Uint8List.fromList([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for negative offset', () {
      final bytes = Uint8List.fromList([0x80]);
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, -1),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for offset past end', () {
      final bytes = Uint8List.fromList([0x80]);
      expect(
        () => QpackDecoder.decodeFieldLine(bytes, 2),
        throwsArgumentError,
      );
    });

    test('decodeFieldLines returns empty list for empty bytes', () {
      final decoded = QpackDecoder.decodeFieldLines(Uint8List(0));
      expect(decoded, isEmpty);
    });

    test('decodeFieldLine throws for indexed entry with null value', () {
      // Static table index 1 is ':authority' which has no value.
      // Indexed representation: 1 + 6-bit prefix.
      final indexBytes = QpackInteger.encode(1, 6);
      indexBytes[0] |= 0x80; // Set first bit to 1 for indexed representation
      expect(
        () => QpackDecoder.decodeFieldLine(indexBytes, 0),
        throwsArgumentError,
      );
    });

    test('decodeFieldLine throws for literal with name ref to non-existent index', () {
      // Literal with name reference: 010 + 5-bit prefix encoding of a very large index.
      final indexBytes = QpackInteger.encode(0xFFFFFF, 5);
      indexBytes[0] |= 0x40; // Set first bits to 010
      expect(
        () => QpackDecoder.decodeFieldLine(indexBytes, 0),
        throwsArgumentError,
      );
    });

    test('QpackFieldLine toString', () {
      const line = QpackFieldLine(':method', 'GET');
      expect(line.toString(), equals('QpackFieldLine(:method: GET)'));
    });
  });
}

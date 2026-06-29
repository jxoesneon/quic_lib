import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_decoder.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';
import 'package:quic_lib/src/http3/qpack_integer.dart';
import 'package:quic_lib/src/http3/qpack_static_table.dart';
import 'package:quic_lib/src/http3/qpack_string.dart';
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
      final bytes = Uint8List.fromList(
          [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
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
      // Static table index 0 is ':authority' which has no value.
      // Indexed representation: 0 + 6-bit prefix.
      final indexBytes = QpackInteger.encode(0, 6);
      indexBytes[0] |= 0x80; // Set first bit to 1 for indexed representation
      expect(
        () => QpackDecoder.decodeFieldLine(indexBytes, 0),
        throwsArgumentError,
      );
    });

    test(
        'decodeFieldLine throws for literal with name ref to non-existent index',
        () {
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

    test('decode rejects out-of-bounds offset', () {
      final decoder = QpackDecoder();
      expect(() => decoder.decode(Uint8List.fromList([0x80]), 2),
          throwsArgumentError);
      expect(() => decoder.decode(Uint8List.fromList([0x80]), -1),
          throwsArgumentError);
    });

    test('decode rejects unknown encoding', () {
      final decoder = QpackDecoder();
      // 0x50 does not match any QPACK field-line prefix.
      expect(() => decoder.decode(Uint8List.fromList([0x50]), 0),
          throwsArgumentError);
    });

    test('decodeLinesWithBase sets and restores base', () {
      final decoder = QpackDecoder();
      decoder.base = 5;
      final bytes = Uint8List(0);
      final lines = decoder.decodeLinesWithBase(bytes, 10);
      expect(lines, isEmpty);
      expect(decoder.base, equals(5));
    });

    test('decode indexed with dynamic table entry', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert(':custom', 'dynamic-value');
      final index = QpackStaticTable.length;
      final bytes = QpackInteger.encode(index, 6);
      bytes[0] |= 0x80;
      final (line, _) = decoder.decode(bytes, 0);
      expect(line.name, equals(':custom'));
      expect(line.value, equals('dynamic-value'));
    });

    test('decode indexed with missing dynamic table entry throws', () {
      final decoder = QpackDecoder();
      final index = QpackStaticTable.length + 10;
      final bytes = QpackInteger.encode(index, 6);
      bytes[0] |= 0x80;
      expect(() => decoder.decode(bytes, 0), throwsArgumentError);
    });

    test('decode literal with name ref from dynamic table', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert(':dynamic-name', 'dynamic-value');
      final index = QpackStaticTable.length;
      final indexBytes = QpackInteger.encode(index, 5);
      indexBytes[0] |= 0x40;
      final valueBytes = QpackString.encode('literal-value');
      final bytes = Uint8List.fromList([...indexBytes, ...valueBytes]);
      final (line, _) = decoder.decode(bytes, 0);
      expect(line.name, equals(':dynamic-name'));
      expect(line.value, equals('literal-value'));
    });

    test('decode literal with name ref missing dynamic entry throws', () {
      final decoder = QpackDecoder();
      final index = QpackStaticTable.length + 10;
      final indexBytes = QpackInteger.encode(index, 5);
      indexBytes[0] |= 0x40;
      final valueBytes = QpackString.encode('value');
      final bytes = Uint8List.fromList([...indexBytes, ...valueBytes]);
      expect(() => decoder.decode(bytes, 0), throwsArgumentError);
    });

    test('decode post-base literal with name reference', () {
      final decoder = QpackDecoder();
      decoder.base = 0;
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert(':post-base', 'pb');
      // 0001 prefix + 4-bit encoded post-base index 0.
      final nameIndexBytes = QpackInteger.encode(0, 4);
      nameIndexBytes[0] |= 0x10;
      final valueBytes = QpackString.encode('val');
      final bytes = Uint8List.fromList([...nameIndexBytes, ...valueBytes]);
      final (line, _) = decoder.decode(bytes, 0);
      expect(line.name, equals(':post-base'));
      expect(line.value, equals('val'));
    });

    test('decode post-base literal with missing entry throws', () {
      final decoder = QpackDecoder();
      decoder.base = 0;
      final nameIndexBytes = QpackInteger.encode(0, 4);
      nameIndexBytes[0] |= 0x10;
      final valueBytes = QpackString.encode('val');
      final bytes = Uint8List.fromList([...nameIndexBytes, ...valueBytes]);
      expect(() => decoder.decode(bytes, 0), throwsArgumentError);
    });
  });
}

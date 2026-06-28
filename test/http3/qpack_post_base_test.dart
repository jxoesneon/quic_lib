import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/http3/qpack_decoder.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';

void main() {
  group('QpackEncoder post-base', () {
    test('encodePostBaseIndexed produces bytes starting with 0x00 nibble', () {
      final encoded = QpackEncoder.encodePostBaseIndexed(5);
      expect(encoded[0] & 0xF0, equals(0x00));
    });

    test('encodePostBaseLiteralNameRef produces bytes starting with 0x10', () {
      final encoded = QpackEncoder.encodePostBaseLiteralNameRef(3, 'value');
      expect(encoded[0] & 0xF0, equals(0x10));
    });
  });

  group('QpackDecoder post-base', () {
    test('decode post-base indexed from dynamic table', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert('x-custom', 'first');
      decoder.dynamicTable.insert('x-other', 'second');
      // base = 0, post-base index 0 references the most recent entry (index 0)
      decoder.base = 0;

      final postBaseEncoded = QpackEncoder.encodePostBaseIndexed(0);
      final (line, _) = decoder.decode(postBaseEncoded, 0);
      expect(line.name, equals('x-other'));
      expect(line.value, equals('second'));
    });

    test('decode post-base literal name reference', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert('x-name', 'original');
      decoder.base = 0;

      final encoded = QpackEncoder.encodePostBaseLiteralNameRef(0, 'new-value');
      final (line, _) = decoder.decode(encoded, 0);
      expect(line.name, equals('x-name'));
      expect(line.value, equals('new-value'));
    });

    test('decoder rejects unknown post-base index', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      // Empty dynamic table, any post-base index is invalid
      decoder.base = 0;
      final encoded = QpackEncoder.encodePostBaseIndexed(0);
      expect(
        () => decoder.decode(encoded, 0),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('Round-trip with post-base', () {
    test('encoder/decoder round-trip via post-base literal name ref', () {
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);
      decoder.dynamicTable.insert('x-header', 'first');
      decoder.base = 0;

      final encoded = QpackEncoder.encodePostBaseLiteralNameRef(0, 'second');
      final (line, _) = decoder.decode(encoded, 0);
      expect(line.name, equals('x-header'));
      expect(line.value, equals('second'));
    });
  });
}

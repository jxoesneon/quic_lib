import 'package:test/test.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';
import 'package:quic_lib/src/http3/qpack_decoder.dart';

void main() {
  group('Qpack dynamic table integration', () {
    test('encode then decode a header inserted into dynamic table', () {
      final encoder = QpackEncoder();
      encoder.dynamicTable.setCapacity(4096);
      final decoder = QpackDecoder();
      decoder.dynamicTable.setCapacity(4096);

      const name = 'x-custom-header';
      const value = 'custom-value';

      // First encode: not in any table, should insert into dynamic table
      // and emit literal without name reference.
      final encoded = encoder.encode(name, value);
      expect(encoded[0] & 0xE0, equals(0x20)); // 001 prefix

      // Dynamic table should now contain the entry.
      expect(encoder.dynamicTable.length, equals(1));

      // Decode should round-trip (literal without name ref needs no dynamic table).
      final (decoded, offset) = decoder.decode(encoded, 0);
      expect(decoded.name, equals(name));
      expect(decoded.value, equals(value));
      expect(offset, equals(encoded.length));
    });

    test('dynamic table grows after insertion', () {
      final encoder = QpackEncoder();
      encoder.dynamicTable.setCapacity(4096);
      expect(encoder.dynamicTable.length, equals(0));

      encoder.encode('x-first', 'first-value');
      expect(encoder.dynamicTable.length, equals(1));

      encoder.encode('x-second', 'second-value');
      expect(encoder.dynamicTable.length, equals(2));
    });

    test('second encode of the same header uses dynamic table index', () {
      final encoder = QpackEncoder();
      encoder.dynamicTable.setCapacity(4096);

      const name = 'x-repeat-header';
      const value = 'repeat-value';

      // First encode: inserts into dynamic table.
      final first = encoder.encode(name, value);
      expect(first[0] & 0xE0, equals(0x20)); // literal without name ref

      // Second encode: should reference the dynamic table via indexed representation.
      final second = encoder.encode(name, value);
      expect(second[0] & 0x80, isNonZero); // first bit = 1 (indexed)
    });
  });
}

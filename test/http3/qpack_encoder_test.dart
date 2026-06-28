import 'package:test/test.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';
import 'package:quic_lib/src/http3/qpack_static_table.dart';

void main() {
  group('QpackEncoder', () {
    test('encodeFieldLine with exact static table match', () {
      final bytes = QpackEncoder.encodeFieldLine(':method', 'GET');
      expect(bytes.isNotEmpty, isTrue);
      expect(bytes[0] & 0x80, isNonZero); // First bit = 1 (indexed)
    });

    test('encodeFieldLine with name match but different value', () {
      // Use a method not in the static table
      final bytes = QpackEncoder.encodeFieldLine(':method', 'PROPFIND');
      expect(bytes.isNotEmpty, isTrue);
      // Should be literal with name reference (010 prefix)
      expect(bytes[0] & 0xE0, equals(0x40));
    });

    test('encodeFieldLine with unknown name', () {
      final bytes = QpackEncoder.encodeFieldLine('x-custom-header', 'value');
      expect(bytes.isNotEmpty, isTrue);
      // Should be literal without name reference (001 prefix)
      expect(bytes[0] & 0xE0, equals(0x20));
    });

    test('encodeFieldLines with multiple lines', () {
      final bytes = QpackEncoder.encodeFieldLines([
        (name: ':method', value: 'GET'),
        (name: ':scheme', value: 'https'),
      ]);
      expect(bytes.isNotEmpty, isTrue);
    });

    test('findStaticIndex returns correct index', () {
      final index = QpackEncoder.findStaticIndex(':method', 'GET');
      expect(index, isNotNull);
      final entry = QpackStaticTable.get(index!);
      expect(entry!.name, equals(':method'));
      expect(entry.value, equals('GET'));
    });

    test('findStaticIndex returns null for unknown', () {
      expect(QpackEncoder.findStaticIndex('x-unknown', 'value'), isNull);
    });

    test('findStaticNameIndex returns correct index', () {
      final index = QpackEncoder.findStaticNameIndex(':authority');
      expect(index, isNotNull);
      expect(QpackStaticTable.get(index!)!.name, equals(':authority'));
    });

    test('findStaticNameIndex returns null for unknown', () {
      expect(QpackEncoder.findStaticNameIndex('x-unknown'), isNull);
    });
  });
}

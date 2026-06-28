import 'package:test/test.dart';
import 'package:quic_lib/src/http3/qpack_static_table.dart';

void main() {
  group('QpackStaticTable', () {
    test('get returns correct entry for known indices', () {
      final entry = QpackStaticTable.get(1);
      expect(entry, isNotNull);
      expect(entry!.name, equals(':authority'));
    });

    test('get returns null for out-of-bounds', () {
      expect(QpackStaticTable.get(0), isNull);
      expect(QpackStaticTable.get(1000), isNull);
    });

    test('findIndex finds exact name+value match', () {
      final index = QpackStaticTable.findIndex(':method', 'GET');
      expect(index, isNotNull);
      final entry = QpackStaticTable.get(index!);
      expect(entry!.name, equals(':method'));
      expect(entry.value, equals('GET'));
    });

    test('findIndex finds name-only match', () {
      final index = QpackStaticTable.findIndex(':authority');
      expect(index, isNotNull);
      expect(QpackStaticTable.get(index!)!.name, equals(':authority'));
    });

    test('findIndex returns null for unknown name', () {
      expect(QpackStaticTable.findIndex('x-unknown-header'), isNull);
    });

    test('length matches entries count', () {
      expect(QpackStaticTable.length, equals(170));
    });

    test('all entries have non-empty names', () {
      for (var i = 1; i <= QpackStaticTable.length; i++) {
        final entry = QpackStaticTable.get(i);
        expect(entry, isNotNull);
        expect(entry!.name.isNotEmpty, isTrue);
      }
    }, tags: ['slow']);
  });
}

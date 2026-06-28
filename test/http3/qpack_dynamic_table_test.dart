import 'package:test/test.dart';
import 'package:quic_lib/src/http3/qpack_dynamic_table.dart';
import 'package:quic_lib/src/http3/qpack_static_table.dart';

void main() {
  group('QpackDynamicTable', () {
    test('insert entries and retrieve by index', () {
      final table = QpackDynamicTable(capacity: 1024);
      expect(table.length, equals(0));

      table.insert('x-foo', 'bar');
      expect(table.length, equals(1));
      expect(table.get(0)?.name, equals('x-foo'));
      expect(table.get(0)?.value, equals('bar'));

      table.insert('x-baz', 'qux');
      expect(table.length, equals(2));
      expect(table.get(0)?.name, equals('x-baz')); // most recent
      expect(table.get(1)?.name, equals('x-foo')); // older
      expect(table.get(2), isNull);
      expect(table.get(-1), isNull);
    });

    test('capacity eviction removes oldest entries', () {
      // Each entry: 32 + 5 + 3 = 40 bytes (x-foo/bar)
      // capacity = 70 bytes => can hold 1 entry, second insert evicts first
      final table = QpackDynamicTable(capacity: 70);
      table.insert('x-foo', 'bar');
      expect(table.length, equals(1));
      table.insert('x-baz', 'qux');
      // Size would be 80 > 70, so oldest (x-foo) is evicted
      expect(table.length, equals(1));
      expect(table.get(0)?.name, equals('x-baz'));
    });

    test('setCapacity with lower value evicts', () {
      final table = QpackDynamicTable(capacity: 1024);
      table.insert('x-foo', 'bar');
      table.insert('x-baz', 'qux');
      expect(table.length, equals(2));

      table.setCapacity(40); // Only enough for one entry
      expect(table.length, equals(1));
      expect(table.get(0)?.name, equals('x-baz')); // most recent kept
    });

    test('find returns correct index', () {
      final table = QpackDynamicTable(capacity: 1024);
      table.insert('x-foo', 'bar');
      table.insert('x-baz', 'qux');
      table.insert('x-foo', 'updated');

      // find by name only, searches from tail
      expect(table.find('x-foo'), equals(0)); // most recent x-foo
      expect(table.find('x-baz'), equals(1));
      expect(table.find('x-unknown'), isNull);

      // find by name and value
      expect(table.find('x-foo', 'updated'), equals(0));
      expect(table.find('x-foo', 'bar'), equals(2)); // oldest x-foo
      expect(table.find('x-foo', 'nonexistent'), isNull);
    });

    test('size calculation is correct', () {
      final table = QpackDynamicTable(capacity: 1024);
      table.insert('ab', 'cd');
      // 32 + 2 + 2 = 36
      expect(table.size, equals(36));
    });

    test('capacity getter reflects setCapacity', () {
      final table = QpackDynamicTable(capacity: 100);
      expect(table.capacity, equals(100));
      table.setCapacity(200);
      expect(table.capacity, equals(200));
    });
  });

  group('encodeWithDynamicTable', () {
    test('uses dynamic reference when exact match available', () {
      final table = QpackDynamicTable(capacity: 1024);
      table.insert('x-custom', 'value');

      final bytes = encodeWithDynamicTable('x-custom', 'value', table);
      // Dynamic indexed: 11 + 6-bit prefix
      expect(bytes[0] & 0xC0, equals(0xC0));
      // Index 0 should fit in first byte (0 < 63)
      expect(bytes[0] & 0x3F, equals(0));
    });

    test('falls back to static table exact match', () {
      final table = QpackDynamicTable(capacity: 1024);

      final bytes = encodeWithDynamicTable(':method', 'GET', table);
      // Static indexed: 10 + 6-bit prefix
      expect(bytes[0] & 0xC0, equals(0x80));
      // Should reference static table index (1-based, non-zero)
      expect(bytes[0] & 0x3F, isNonZero);
    });

    test('uses dynamic name reference when name match available', () {
      final table = QpackDynamicTable(capacity: 1024);
      table.insert('x-custom', 'old-value');

      final bytes = encodeWithDynamicTable('x-custom', 'new-value', table);
      // Literal with dynamic name reference: 011 + 5-bit prefix
      expect(bytes[0] & 0xE0, equals(0x60));
    });

    test('falls back to static name reference', () {
      final table = QpackDynamicTable(capacity: 1024);

      final bytes = encodeWithDynamicTable(':method', 'PROPFIND', table);
      // Literal with static name reference: 010 + 5-bit prefix
      expect(bytes[0] & 0xE0, equals(0x40));
    });

    test('falls back to literal without name reference', () {
      final table = QpackDynamicTable(capacity: 1024);

      final bytes = encodeWithDynamicTable('x-unknown-header', 'value', table);
      // Literal without name reference: 001 + 5-bit prefix
      expect(bytes[0] & 0xE0, equals(0x20));
    });
  });
}

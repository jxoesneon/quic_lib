import 'dart:typed_data';

import 'qpack_integer.dart';
import 'qpack_static_table.dart';
import 'qpack_string.dart';

/// QPACK dynamic table per RFC 9204 Section 3.
///
/// The dynamic table is a list of field lines that can be referenced by index.
/// Entries are inserted at the tail and evicted from the head when capacity
/// would be exceeded.
class QpackDynamicTable {
  int _capacity;
  final List<({String name, String value})> _entries = [];

  QpackDynamicTable({int capacity = 0}) : _capacity = capacity;

  /// Maximum capacity of the dynamic table in bytes.
  int get capacity => _capacity;

  /// Current size of the dynamic table in bytes.
  ///
  /// Per RFC 9204 Section 3.2, the size of an entry is the sum of its name's
  /// length in octets, its value's length in octets, and 32.
  int get size =>
      _entries.fold(0, (s, e) => s + 32 + e.name.length + e.value.length);

  /// Number of entries in the dynamic table.
  int get length => _entries.length;

  /// Insert a new entry at the tail (most recent).
  ///
  /// After insertion, entries are evicted from the head until
  /// [size] is less than or equal to [capacity].
  void insert(String name, String value) {
    _entries.add((name: name, value: value));
    while (size > _capacity) {
      _entries.removeAt(0);
    }
  }

  /// Retrieve an entry by 0-based index from the tail.
  ///
  /// Index 0 is the most recent entry. Returns `null` if the index is out of
  /// bounds.
  ({String name, String value})? get(int index) {
    if (index < 0 || index >= _entries.length) return null;
    return _entries[_entries.length - 1 - index];
  }

  /// Find the first entry matching [name] (and optionally [value]),
  /// searching from the tail towards the head.
  ///
  /// Returns the 0-based index from the tail, or `null` if not found.
  int? find(String name, [String? value]) {
    for (var i = _entries.length - 1; i >= 0; i--) {
      final entry = _entries[i];
      if (entry.name == name) {
        if (value == null || entry.value == value) {
          return _entries.length - 1 - i;
        }
      }
    }
    return null;
  }

  /// Update the capacity and evict entries from the head if needed.
  void setCapacity(int newCapacity) {
    _capacity = newCapacity;
    while (size > _capacity) {
      _entries.removeAt(0);
    }
  }
}

/// Encode a field line using the dynamic table when possible.
///
/// Tries in order:
/// 1. Exact match in dynamic table (indexed with dynamic reference)
/// 2. Exact match in static table (indexed with static reference)
/// 3. Name match in dynamic table (literal with dynamic name reference)
/// 4. Name match in static table (literal with static name reference)
/// 5. Literal without name reference
Uint8List encodeWithDynamicTable(
  String name,
  String value,
  QpackDynamicTable table,
) {
  // 1. Dynamic table exact match
  final dynamicIndex = table.find(name, value);
  if (dynamicIndex != null) {
    final bytes = QpackInteger.encode(dynamicIndex, 6);
    bytes[0] |= 0xC0; // 11 prefix for dynamic indexed
    return bytes;
  }

  // 2. Static table exact match
  final staticIndex = QpackStaticTable.findIndex(name, value);
  if (staticIndex != null) {
    final bytes = QpackInteger.encode(staticIndex, 6);
    bytes[0] |= 0x80; // 10 prefix for static indexed
    return bytes;
  }

  // 3. Dynamic table name-only match
  final dynamicNameIndex = table.find(name);
  if (dynamicNameIndex != null) {
    final builder = BytesBuilder();
    final indexBytes = QpackInteger.encode(dynamicNameIndex, 5);
    indexBytes[0] |= 0x60; // 011 prefix for literal with dynamic name reference
    builder.add(indexBytes);
    builder.add(QpackString.encode(value));
    return Uint8List.fromList(builder.toBytes());
  }

  // 4. Static table name-only match
  final staticNameIndex = QpackStaticTable.findIndex(name);
  if (staticNameIndex != null) {
    final builder = BytesBuilder();
    final indexBytes = QpackInteger.encode(staticNameIndex, 5);
    indexBytes[0] |= 0x40; // 010 prefix for literal with static name reference
    builder.add(indexBytes);
    builder.add(QpackString.encode(value));
    return Uint8List.fromList(builder.toBytes());
  }

  // 5. Literal without name reference
  final builder = BytesBuilder();
  final prefix = Uint8List(1)..[0] = 0x20; // 001 prefix
  builder.add(prefix);
  builder.add(QpackString.encode(name));
  builder.add(QpackString.encode(value));
  return Uint8List.fromList(builder.toBytes());
}

import 'dart:typed_data';
import 'qpack_dynamic_table.dart';
import 'qpack_integer.dart';
import 'qpack_string.dart';
import 'qpack_static_table.dart';

/// QPACK field line encoder per RFC 9204 Section 4.3.
/// Supports both static and dynamic table lookups.
class QpackEncoder {
  QpackEncoder();

  /// Dynamic table for this encoder.
  final QpackDynamicTable dynamicTable = QpackDynamicTable(capacity: 0);

  /// Encode a single field line using both static and dynamic tables.
  Uint8List encode(String name, String value) {
    // Try dynamic table exact match first
    final dynamicExact = dynamicTable.find(name, value);
    if (dynamicExact != null) {
      return _encodeIndexed(QpackStaticTable.length + dynamicExact);
    }

    // Try dynamic table name-only match
    final dynamicName = dynamicTable.find(name);
    if (dynamicName != null) {
      return _encodeLiteralWithNameRef(
          QpackStaticTable.length + dynamicName, value);
    }

    // Try exact static table match
    final exactIndex = findStaticIndex(name, value);
    if (exactIndex != null) {
      return _encodeIndexed(exactIndex);
    }

    // Try name-only static table match
    final nameIndex = findStaticNameIndex(name);
    if (nameIndex != null) {
      return _encodeLiteralWithNameRef(nameIndex, value);
    }

    // Insert into dynamic table and emit literal without name reference
    dynamicTable.insert(name, value);
    return _encodeLiteralWithoutNameRef(name, value);
  }

  /// Encode multiple field lines.
  Uint8List encodeLines(List<({String name, String value})> lines) {
    final builder = BytesBuilder();
    for (final line in lines) {
      builder.add(encode(line.name, line.value));
    }
    return Uint8List.fromList(builder.toBytes());
  }

  /// Encode a single field line using only the static table.
  static Uint8List encodeFieldLine(String name, String value) {
    // Try exact match first (indexed representation)
    final exactIndex = findStaticIndex(name, value);
    if (exactIndex != null) {
      return _encodeIndexed(exactIndex);
    }

    // Try name-only match (literal with name reference)
    final nameIndex = findStaticNameIndex(name);
    if (nameIndex != null) {
      return _encodeLiteralWithNameRef(nameIndex, value);
    }

    // Literal without name reference
    return _encodeLiteralWithoutNameRef(name, value);
  }

  /// Encode multiple field lines using only the static table.
  static Uint8List encodeFieldLines(List<({String name, String value})> lines) {
    final builder = BytesBuilder();
    for (final line in lines) {
      builder.add(encodeFieldLine(line.name, line.value));
    }
    return Uint8List.fromList(builder.toBytes());
  }

  /// Find a static table index for an exact name+value match.
  /// Returns the 1-based index or null.
  static int? findStaticIndex(String name, String value) {
    for (var i = 1; i <= QpackStaticTable.length; i++) {
      final entry = QpackStaticTable.get(i)!;
      if (entry.name == name && entry.value == value) {
        return i;
      }
    }
    return null;
  }

  /// Find the first static table index for a given name.
  /// Returns the 1-based index or null.
  static int? findStaticNameIndex(String name) {
    for (var i = 1; i <= QpackStaticTable.length; i++) {
      final entry = QpackStaticTable.get(i)!;
      if (entry.name == name) {
        return i;
      }
    }
    return null;
  }

  // Indexed representation: 1 + 6-bit prefix
  static Uint8List _encodeIndexed(int index) {
    final encoded = QpackInteger.encode(index, 6);
    encoded[0] |= 0x80; // Set first bit to 1
    return encoded;
  }

  // Literal with name reference: 010 + 5-bit prefix
  static Uint8List _encodeLiteralWithNameRef(int nameIndex, String value) {
    final builder = BytesBuilder();
    final indexBytes = QpackInteger.encode(nameIndex, 5);
    indexBytes[0] |= 0x40; // Set first bits to 010
    builder.add(indexBytes);
    builder.add(QpackString.encode(value));
    return Uint8List.fromList(builder.toBytes());
  }

  // Literal without name reference: 001 + 5-bit prefix
  static Uint8List _encodeLiteralWithoutNameRef(String name, String value) {
    final builder = BytesBuilder();
    final prefix = Uint8List(1)..[0] = 0x20; // 00100000
    builder.add(prefix);
    builder.add(QpackString.encode(name));
    builder.add(QpackString.encode(value));
    return Uint8List.fromList(builder.toBytes());
  }

  /// Compute the Required Insert Count for a dynamic table reference.
  ///
  /// Per RFC 9204 Errata 8410, the correct formula is:
  /// `requiredInsertCount = max(requiredInsertCount, dynamicIndex + 1)`.
  static int requiredInsertCount(int current, int dynamicIndex) {
    return current > dynamicIndex + 1 ? current : dynamicIndex + 1;
  }

  // Post-base indexed representation: 0000 + 4-bit prefix (Section 4.5.3)
  static Uint8List encodePostBaseIndexed(int postBaseIndex) {
    final encoded = QpackInteger.encode(postBaseIndex, 4);
    // First nibble must be 0000 — QpackInteger already writes the value into
    // the lower bits, leaving the upper 4 bits as 0.
    return encoded;
  }

  // Post-base literal with name reference: 0001 + 4-bit prefix + value
  static Uint8List encodePostBaseLiteralNameRef(
      int postBaseNameIndex, String value) {
    final builder = BytesBuilder();
    final indexBytes = QpackInteger.encode(postBaseNameIndex, 4);
    indexBytes[0] |= 0x10; // Set first nibble to 0001
    builder.add(indexBytes);
    builder.add(QpackString.encode(value));
    return Uint8List.fromList(builder.toBytes());
  }
}

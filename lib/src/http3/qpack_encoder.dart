import 'dart:typed_data';
import 'qpack_integer.dart';
import 'qpack_string.dart';
import 'qpack_static_table.dart';

/// QPACK field line encoder per RFC 9204 Section 4.3.
/// For now, only static table lookups are supported (no dynamic table).
class QpackEncoder {
  QpackEncoder._();

  /// Encode a single field line.
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

  /// Encode multiple field lines.
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
}

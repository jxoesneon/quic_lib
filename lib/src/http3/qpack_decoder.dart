import 'dart:typed_data';

import 'qpack_dynamic_table.dart';
import 'qpack_integer.dart';
import 'qpack_static_table.dart';
import 'qpack_string.dart';

/// A decoded QPACK field line.
class QpackFieldLine {
  final String name;
  final String value;

  const QpackFieldLine(this.name, this.value);

  @override
  String toString() => 'QpackFieldLine($name: $value)';
}

/// QPACK field line decoder per RFC 9204 Section 4.3.
///
/// Supports both static and dynamic table lookups.
class QpackDecoder {
  QpackDecoder();

  /// Dynamic table for this decoder.
  final QpackDynamicTable dynamicTable = QpackDynamicTable(capacity: 0);

  /// Base index for post-base indexing (RFC 9204 Section 4.5.3/4.5.5).
  /// Defaults to 0; callers should update this before decoding a header block.
  int base = 0;

  /// Decode a single field line from [bytes] starting at [offset].
  ///
  /// Returns a record `(fieldLine, newOffset)` where `newOffset` is the
  /// first byte after the decoded field line.
  (QpackFieldLine, int) decode(Uint8List bytes, int offset) {
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    final firstByte = bytes[offset];

    // Indexed representation: first bit = 1
    if ((firstByte & 0x80) != 0) {
      return _decodeIndexed(bytes, offset, dynamicTable);
    }

    // Literal with name reference: first bits = 010
    if ((firstByte & 0xE0) == 0x40) {
      return _decodeLiteralWithNameRef(bytes, offset, dynamicTable);
    }

    // Literal without name reference: first bits = 001
    if ((firstByte & 0xE0) == 0x20) {
      return _decodeLiteralWithoutNameRef(bytes, offset);
    }

    // Post-base indexed: first nibble = 0000 (Section 4.5.3)
    if ((firstByte & 0xF0) == 0x00) {
      return _decodePostBaseIndexed(bytes, offset);
    }

    // Post-base literal with name reference: first nibble = 0001 (Section 4.5.5)
    if ((firstByte & 0xF0) == 0x10) {
      return _decodePostBaseLiteralNameRef(bytes, offset);
    }

    throw ArgumentError(
      'Unknown QPACK field line encoding at offset $offset: 0x${firstByte.toRadixString(16)}',
    );
  }

  /// Decode multiple field lines from [bytes].
  List<QpackFieldLine> decodeLines(Uint8List bytes) {
    final lines = <QpackFieldLine>[];
    var offset = 0;
    while (offset < bytes.length) {
      final (line, newOffset) = decode(bytes, offset);
      lines.add(line);
      offset = newOffset;
    }
    return lines;
  }

  /// Decode a single field line from [bytes] starting at [offset]
  /// using only the static table.
  static (QpackFieldLine, int) decodeFieldLine(Uint8List bytes, int offset) {
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    final firstByte = bytes[offset];

    // Indexed representation: first bit = 1
    if ((firstByte & 0x80) != 0) {
      return _decodeIndexed(bytes, offset);
    }

    // Literal with name reference: first bits = 010
    if ((firstByte & 0xE0) == 0x40) {
      return _decodeLiteralWithNameRef(bytes, offset);
    }

    // Literal without name reference: first bits = 001
    if ((firstByte & 0xE0) == 0x20) {
      return _decodeLiteralWithoutNameRef(bytes, offset);
    }

    throw ArgumentError(
      'Unknown QPACK field line encoding at offset $offset: 0x${firstByte.toRadixString(16)}',
    );
  }

  /// Decode multiple field lines from [bytes] using only the static table.
  static List<QpackFieldLine> decodeFieldLines(Uint8List bytes) {
    final lines = <QpackFieldLine>[];
    var offset = 0;
    while (offset < bytes.length) {
      final (line, newOffset) = decodeFieldLine(bytes, offset);
      lines.add(line);
      offset = newOffset;
    }
    return lines;
  }

  // Indexed representation: 1 + 6-bit prefix
  static (QpackFieldLine, int) _decodeIndexed(
    Uint8List bytes,
    int offset, [
    QpackDynamicTable? dynamicTable,
  ]) {
    final (index, newOffset) = QpackInteger.decode(bytes, offset, 6);

    if (dynamicTable != null && index >= QpackStaticTable.length) {
      final dynamicIndex = index - QpackStaticTable.length;
      final entry = dynamicTable.get(dynamicIndex);
      if (entry != null) {
        return (QpackFieldLine(entry.name, entry.value), newOffset);
      }
      throw ArgumentError('Dynamic table index $dynamicIndex not found');
    }

    final entry = QpackStaticTable.get(index);
    if (entry == null) {
      throw ArgumentError('Static table index $index not found');
    }
    final name = entry.name;
    final value = entry.value;
    if (value == null) {
      throw ArgumentError('Static table index $index has no value');
    }
    return (QpackFieldLine(name, value), newOffset);
  }

  // Literal with name reference: 010 + 5-bit prefix
  static (QpackFieldLine, int) _decodeLiteralWithNameRef(
    Uint8List bytes,
    int offset, [
    QpackDynamicTable? dynamicTable,
  ]) {
    final (nameIndex, nameOffset) = QpackInteger.decode(bytes, offset, 5);

    if (dynamicTable != null && nameIndex >= QpackStaticTable.length) {
      final dynamicNameIndex = nameIndex - QpackStaticTable.length;
      final entry = dynamicTable.get(dynamicNameIndex);
      if (entry == null) {
        throw ArgumentError(
          'Dynamic table name index $dynamicNameIndex not found',
        );
      }
      final (value, valueOffset) = QpackString.decode(bytes, nameOffset);
      return (QpackFieldLine(entry.name, value), valueOffset);
    }

    final entry = QpackStaticTable.get(nameIndex);
    if (entry == null) {
      throw ArgumentError('Static table name index $nameIndex not found');
    }
    final (value, valueOffset) = QpackString.decode(bytes, nameOffset);
    return (QpackFieldLine(entry.name, value), valueOffset);
  }

  // Literal without name reference: 001 + 5-bit prefix
  static (QpackFieldLine, int) _decodeLiteralWithoutNameRef(
      Uint8List bytes, int offset) {
    // Skip the 5-bit prefix (which is always 0 for this instruction).
    final nameOffset = offset + 1;
    final (name, nameEnd) = QpackString.decode(bytes, nameOffset);
    final (value, valueEnd) = QpackString.decode(bytes, nameEnd);
    return (QpackFieldLine(name, value), valueEnd);
  }

  // Post-base indexed: 0000 + 4-bit prefix (Section 4.5.3)
  (QpackFieldLine, int) _decodePostBaseIndexed(
    Uint8List bytes,
    int offset,
  ) {
    final (postBaseIndex, newOffset) = QpackInteger.decode(bytes, offset, 4);
    final absoluteIndex = base + postBaseIndex;
    final entry = dynamicTable.get(absoluteIndex);
    if (entry == null) {
      throw ArgumentError(
        'Post-base dynamic table index $postBaseIndex (absolute $absoluteIndex) not found',
      );
    }
    return (QpackFieldLine(entry.name, entry.value), newOffset);
  }

  // Post-base literal with name reference: 0001 + 4-bit prefix (Section 4.5.5)
  (QpackFieldLine, int) _decodePostBaseLiteralNameRef(
    Uint8List bytes,
    int offset,
  ) {
    final (postBaseNameIndex, nameOffset) =
        QpackInteger.decode(bytes, offset, 4);
    final absoluteNameIndex = base + postBaseNameIndex;
    final entry = dynamicTable.get(absoluteNameIndex);
    if (entry == null) {
      throw ArgumentError(
        'Post-base dynamic table name index $postBaseNameIndex (absolute $absoluteNameIndex) not found',
      );
    }
    final (value, valueOffset) = QpackString.decode(bytes, nameOffset);
    return (QpackFieldLine(entry.name, value), valueOffset);
  }
}

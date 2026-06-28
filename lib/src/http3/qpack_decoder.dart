import 'dart:typed_data';

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
/// Supports static table lookups. Dynamic table support can be added
/// by providing a dynamicTable callback.
class QpackDecoder {
  QpackDecoder._();

  /// Decode a single field line from [bytes] starting at [offset].
  ///
  /// Returns a record `(fieldLine, newOffset)` where `newOffset` is the
  /// first byte after the decoded field line.
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

  /// Decode multiple field lines from [bytes].
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
  static (QpackFieldLine, int) _decodeIndexed(Uint8List bytes, int offset) {
    final (index, newOffset) = QpackInteger.decode(bytes, offset, 6);
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
      Uint8List bytes, int offset) {
    final (nameIndex, nameOffset) = QpackInteger.decode(bytes, offset, 5);
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
}

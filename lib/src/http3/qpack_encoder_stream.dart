import 'dart:convert';
import 'dart:typed_data';

import 'qpack_integer.dart';
import 'qpack_string.dart';

/// Abstract base class for QPACK encoder stream instructions per RFC 9204
/// Section 4.3.
///
/// These instructions are sent on the encoder stream (0x02) to update the
/// dynamic table.
abstract class EncoderInstruction {
  /// Serialize this instruction to bytes.
  Uint8List serialize();

  /// Parse a single encoder instruction from [bytes].
  ///
  /// Returns the decoded instruction instance.
  ///
  /// Throws [ArgumentError] if the bytes do not represent a valid
  /// instruction or if the buffer is too short.
  static EncoderInstruction parse(Uint8List bytes) {
    if (bytes.isEmpty) {
      throw ArgumentError(
        'Empty bytes cannot be parsed as an encoder instruction',
      );
    }

    final firstByte = bytes[0];

    // Insert with Name Reference: first bit = 1 (Section 4.3.2).
    if ((firstByte & 0x80) != 0) {
      return InsertWithNameReference._parse(bytes);
    }

    // Insert with Literal Name: first two bits = 01 (Section 4.3.3).
    if ((firstByte & 0xC0) == 0x40) {
      return InsertWithoutNameReference._parse(bytes);
    }

    // Set Dynamic Table Capacity: first three bits = 001 (Section 4.3.1).
    if ((firstByte & 0xE0) == 0x20) {
      return SetDynamicTableCapacity._parse(bytes);
    }

    // Duplicate: first three bits = 000 (Section 4.3.4).
    if ((firstByte & 0xE0) == 0x00) {
      return Duplicate._parse(bytes);
    }

    throw ArgumentError(
      'Unknown encoder instruction: 0x${firstByte.toRadixString(16).padLeft(2, '0')}',
    );
  }
}

/// RFC 9204 Section 4.3.2 — Insert with Name Reference.
///
/// Adds a dynamic table entry whose field name matches an existing entry in
/// the static or dynamic table. The field value is transmitted as a string
/// literal.
///
/// Wire format:
/// ```
/// | 1 | T |    Name Index (6+)    |
/// | H |     Value Length (7+)     |
/// |  Value String (Length bytes)   |
/// ```
class InsertWithNameReference extends EncoderInstruction {
  /// `true` when the name reference points to the static table (T=1);
  /// `false` when it points to the dynamic table (T=0).
  final bool isStatic;

  /// The index of the name in the referenced table.
  final int nameIndex;

  /// The field value to store in the new dynamic table entry.
  final String value;

  InsertWithNameReference({
    required this.isStatic,
    required this.nameIndex,
    required this.value,
  });

  @override
  Uint8List serialize() {
    final indexBytes = QpackInteger.encode(nameIndex, 6);
    indexBytes[0] |= 0x80; // instruction prefix '1'
    if (isStatic) {
      indexBytes[0] |= 0x40; // T = 1
    }

    final valueBytes = QpackString.encode(value);
    final result = Uint8List(indexBytes.length + valueBytes.length);
    result.setRange(0, indexBytes.length, indexBytes);
    result.setRange(indexBytes.length, result.length, valueBytes);

    return result;
  }

  static InsertWithNameReference _parse(Uint8List bytes) {
    final (nameIndex, valueOffset) = QpackInteger.decode(bytes, 0, 6);
    final isStatic = (bytes[0] & 0x40) != 0;
    final (value, _) = QpackString.decode(bytes, valueOffset);

    return InsertWithNameReference(
      isStatic: isStatic,
      nameIndex: nameIndex,
      value: value,
    );
  }

  @override
  String toString() =>
      'InsertWithNameReference(isStatic: $isStatic, nameIndex: $nameIndex, '
      'value: $value)';
}

/// RFC 9204 Section 4.3.3 — Insert with Literal Name.
///
/// Adds a dynamic table entry where both the field name and field value are
/// transmitted as string literals.
///
/// Wire format:
/// ```
/// | 0 | 1 | H | Name Length (5+)  |
/// |  Name String (Length bytes)   |
/// | H |     Value Length (7+)     |
/// |  Value String (Length bytes)   |
/// ```
class InsertWithoutNameReference extends EncoderInstruction {
  /// The literal field name.
  final String name;

  /// The literal field value.
  final String value;

  InsertWithoutNameReference({
    required this.name,
    required this.value,
  });

  @override
  Uint8List serialize() {
    final nameUtf8 = utf8.encode(name);
    final nameLengthBytes = QpackInteger.encode(nameUtf8.length, 5);
    nameLengthBytes[0] |= 0x40; // instruction prefix '01'
    // Huffman flag (bit 5) is left as 0 — raw UTF-8.

    final valueBytes = QpackString.encode(value);

    final result = Uint8List(
      nameLengthBytes.length + nameUtf8.length + valueBytes.length,
    );
    result.setRange(0, nameLengthBytes.length, nameLengthBytes);
    result.setRange(
      nameLengthBytes.length,
      nameLengthBytes.length + nameUtf8.length,
      nameUtf8,
    );
    result.setRange(
      nameLengthBytes.length + nameUtf8.length,
      result.length,
      valueBytes,
    );

    return result;
  }

  static InsertWithoutNameReference _parse(Uint8List bytes) {
    final (nameLength, nameStart) = QpackInteger.decode(bytes, 0, 5);
    if (nameStart + nameLength > bytes.length) {
      throw ArgumentError(
        'Name length $nameLength exceeds buffer at offset $nameStart',
      );
    }

    final name = utf8.decode(
      bytes.sublist(nameStart, nameStart + nameLength),
    );

    final (value, _) = QpackString.decode(bytes, nameStart + nameLength);

    return InsertWithoutNameReference(name: name, value: value);
  }

  @override
  String toString() =>
      'InsertWithoutNameReference(name: $name, value: $value)';
}

/// RFC 9204 Section 4.3.4 — Duplicate.
///
/// Duplicates an existing entry in the dynamic table.
///
/// Wire format:
/// ```
/// | 0 | 0 | 0 |    Index (5+)     |
/// ```
class Duplicate extends EncoderInstruction {
  /// The relative index of the existing entry to duplicate.
  final int index;

  Duplicate({required this.index});

  @override
  Uint8List serialize() {
    // The upper 3 bits are already 0 from QpackInteger.encode.
    return QpackInteger.encode(index, 5);
  }

  static Duplicate _parse(Uint8List bytes) {
    final (index, _) = QpackInteger.decode(bytes, 0, 5);
    return Duplicate(index: index);
  }

  @override
  String toString() => 'Duplicate(index: $index)';
}

/// RFC 9204 Section 4.3.1 — Set Dynamic Table Capacity.
///
/// Changes the capacity of the dynamic table.
///
/// Wire format:
/// ```
/// | 0 | 0 | 1 |   Capacity (5+)   |
/// ```
class SetDynamicTableCapacity extends EncoderInstruction {
  /// The new dynamic table capacity.
  final int capacity;

  SetDynamicTableCapacity({required this.capacity});

  @override
  Uint8List serialize() {
    final capBytes = QpackInteger.encode(capacity, 5);
    capBytes[0] |= 0x20; // instruction prefix '001'
    return capBytes;
  }

  static SetDynamicTableCapacity _parse(Uint8List bytes) {
    final (capacity, _) = QpackInteger.decode(bytes, 0, 5);
    return SetDynamicTableCapacity(capacity: capacity);
  }

  @override
  String toString() => 'SetDynamicTableCapacity(capacity: $capacity)';
}

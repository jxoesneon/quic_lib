import 'dart:convert';
import 'dart:typed_data';

import 'huffman.dart';
import 'qpack_integer.dart';

/// QPACK string literal encoder/decoder per RFC 9204 Section 4.2 (same as
/// RFC 7541 §6.2).
///
/// The first byte contains:
///   - bit 7 (0x80): Huffman flag (1 = Huffman-coded, 0 = raw)
///   - bits 6-0: length prefix (7 bits)
///
/// If the length fits in 7 bits it is encoded in the first byte; otherwise the
/// prefix is all-ones and the remainder follows in multi-byte continuation.
/// The string bytes (raw UTF-8; Huffman coding is reserved for future use) are
/// appended after the length.
class QpackString {
  QpackString._();

  /// Encode [value] as a QPACK string literal.
  ///
  /// When [huffman] is `true` the payload is Huffman-encoded per RFC 7541
  /// Appendix B and the Huffman flag is set in the first byte.
  static Uint8List encode(String value, {bool huffman = false}) {
    final stringBytes = huffman
        ? HuffmanEncoder.encode(value)
        : Uint8List.fromList(utf8.encode(value));
    final length = stringBytes.length;

    // Encode length into a 7-bit prefix.
    final lengthBytes = QpackInteger.encode(length, 7);
    if (huffman) {
      lengthBytes[0] |= 0x80;
    }

    final result = Uint8List(lengthBytes.length + stringBytes.length);
    result.setRange(0, lengthBytes.length, lengthBytes);
    result.setRange(lengthBytes.length, result.length, stringBytes);

    return result;
  }

  /// Decode a QPACK string literal from [bytes] starting at [offset].
  ///
  /// Returns a record `(value, newOffset)` where `newOffset` is the first byte
  /// after the encoded string.
  ///
  /// Throws [ArgumentError] if the buffer is too short or the encoding is
  /// malformed.
  static (String, int) decode(Uint8List bytes, int offset) {
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    // Decode the length using the 7-bit prefix.  The Huffman flag in bit 7
    // is automatically masked off by QpackInteger.decode.
    final (length, stringOffset) = QpackInteger.decode(bytes, offset, 7);

    if (stringOffset + length > bytes.length) {
      throw ArgumentError(
        'String length $length exceeds remaining buffer at offset $stringOffset',
      );
    }

    final stringBytes = bytes.sublist(stringOffset, stringOffset + length);
    final huffmanFlag = (bytes[offset] & 0x80) != 0;
    final value = huffmanFlag
        ? HuffmanDecoder.decode(stringBytes)
        : utf8.decode(stringBytes);

    return (value, stringOffset + length);
  }
}

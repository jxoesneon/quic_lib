import 'dart:typed_data';

/// QUIC variable-length integer encoding per RFC 9000 Section 16.
///
/// The two most significant bits of the first byte encode the total length:
///   00 → 1 byte  (6 usable bits, max 63)
///   01 → 2 bytes (14 usable bits, max 16383)
///   10 → 4 bytes (30 usable bits, max 1073741823)
///   11 → 8 bytes (62 usable bits, max 4611686018427387903)
///
/// Callers use [encode] to serialize integers and [decode] to recover them
/// from incoming packet buffers. [decodeLength] is useful for parsing when
/// the value itself is not yet needed.
///
/// ## Example
/// ```dart
/// final encoded = VarInt.encode(42);      // 1 byte
/// final value   = VarInt.decode(encoded.buffer); // 42
/// ```
///
/// See also:
/// - [VarInt.encode] — minimal encoding
/// - [VarInt.decode] — deserialization
/// - RFC 9000 Section 16
class VarInt {
  VarInt._();

  /// Maximum value representable by a QUIC varint: 2^62 − 1.
  static int get maxValue => 4611686018427387903; // 0x3FFFFFFFFFFFFFFF

  /// Encodes a non-negative integer into its minimal QUIC varint form.
  ///
  /// Chooses the smallest byte width (1, 2, 4, or 8) that can represent
  /// [value] based on the two most-significant-bit length flag.
  ///
  /// Throws [ArgumentError] if [value] is negative or exceeds [maxValue].
  static Uint8List encode(int value) {
    if (value < 0) {
      throw ArgumentError.value(
        value,
        'value',
        'VarInt value must be non-negative',
      );
    }
    if (value > maxValue) {
      throw ArgumentError.value(
        value,
        'value',
        'VarInt value exceeds maximum $maxValue',
      );
    }

    if (value <= 63) {
      // 1 byte, 2MSB = 00
      return Uint8List(1)..[0] = value;
    } else if (value <= 16383) {
      // 2 bytes, 2MSB = 01
      return Uint8List(2)
        ..[0] = 0x40 | (value >> 8)
        ..[1] = value & 0xFF;
    } else if (value <= 1073741823) {
      // 4 bytes, 2MSB = 10
      return Uint8List(4)
        ..[0] = 0x80 | (value >> 24)
        ..[1] = (value >> 16) & 0xFF
        ..[2] = (value >> 8) & 0xFF
        ..[3] = value & 0xFF;
    } else {
      // 8 bytes, 2MSB = 11
      return Uint8List(8)
        ..[0] = 0xC0 | (value >> 56)
        ..[1] = (value >> 48) & 0xFF
        ..[2] = (value >> 40) & 0xFF
        ..[3] = (value >> 32) & 0xFF
        ..[4] = (value >> 24) & 0xFF
        ..[5] = (value >> 16) & 0xFF
        ..[6] = (value >> 8) & 0xFF
        ..[7] = value & 0xFF;
    }
  }

  /// Decodes a QUIC varint from [buffer] starting at [offset].
  ///
  /// Reads the first byte to determine the total byte length, then reads the
  /// remaining bytes and assembles the integer value.
  ///
  /// Throws [ArgumentError] if the buffer does not contain enough bytes.
  static int decode(ByteBuffer buffer, {int offset = 0}) {
    final bytes = Uint8List.view(buffer);
    if (offset < 0 || offset >= bytes.lengthInBytes) {
      throw ArgumentError(
        'Offset $offset out of bounds for buffer of length '
        '${bytes.lengthInBytes}',
      );
    }

    final firstByte = bytes[offset];
    final length = decodeLength(firstByte);

    if (offset + length > bytes.lengthInBytes) {
      throw ArgumentError(
        'Buffer too short: need $length bytes starting at offset $offset, '
        'but buffer length is ${bytes.lengthInBytes}',
      );
    }

    var value = firstByte & 0x3F;
    for (var i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  /// Returns the total byte length (1, 2, 4, or 8) based on the 2MSB of
  /// [firstByte].
  ///
  /// This is useful when scanning a buffer without fully decoding every
  /// varint, for example to skip over length-prefixed fields.
  static int decodeLength(int firstByte) {
    final lengthFlag = firstByte >> 6;
    return 1 << lengthFlag; // 1, 2, 4, or 8
  }
}

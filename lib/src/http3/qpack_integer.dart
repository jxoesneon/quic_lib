import 'dart:typed_data';

/// QPACK integer encoder/decoder per RFC 9204 Section 4.1.
///
/// QPACK reuses the HPACK integer representation from RFC 7541.  An integer
/// is encoded into the lower [prefixBits] of the first byte; the remaining
/// upper bits of that byte are reserved for the enclosing instruction and are
/// left as zero by these helpers.  Callers must OR in the instruction bits
/// before transmission.
///
///   prefixBits = 1..8
///   prefixLimit = 2^prefixBits - 1
///   If value < prefixLimit: encode in one byte.
///   Else: first byte = prefixLimit, then encode remainder with 7-bit
///   continuation (MSB = 1 for more bytes, 0 for last).
class QpackInteger {
  QpackInteger._();

  /// Maximum value representable by QPACK's 62-bit unsigned integer.
  static const int _maxValue = (1 << 62) - 1;

  /// Encode [value] using a [prefixBits]-bit prefix (1..8).
  ///
  /// Returns a new [Uint8List] whose first byte contains the integer value in
  /// its lower [prefixBits] bits.  The caller is responsible for merging any
  /// instruction bits into the upper bits of the first byte.
  static Uint8List encode(int value, int prefixBits) {
    if (prefixBits < 1 || prefixBits > 8) {
      throw ArgumentError.value(
        prefixBits,
        'prefixBits',
        'must be between 1 and 8',
      );
    }
    if (value < 0) {
      throw ArgumentError.value(value, 'value', 'must be non-negative');
    }
    if (value > _maxValue) {
      throw ArgumentError.value(
        value,
        'value',
        'exceeds maximum $_maxValue',
      );
    }

    final prefixLimit = (1 << prefixBits) - 1;

    // Small enough to fit in the prefix bits of the first byte.
    if (value < prefixLimit) {
      return Uint8List(1)..[0] = value;
    }

    final bytes = <int>[prefixLimit];
    var remaining = value - prefixLimit;

    while (remaining >= 128) {
      bytes.add((remaining & 0x7F) | 0x80);
      remaining >>= 7;
    }
    bytes.add(remaining);

    return Uint8List.fromList(bytes);
  }

  /// Decode a QPACK integer from [bytes] starting at [offset] with the given
  /// [prefixBits].
  ///
  /// Returns a record `(value, newOffset)` where `newOffset` is the first
  /// byte after the encoded integer.
  ///
  /// Throws [ArgumentError] if the buffer is too short or the integer is
  /// malformed.
  static (int, int) decode(Uint8List bytes, int offset, int prefixBits) {
    if (prefixBits < 1 || prefixBits > 8) {
      throw ArgumentError.value(
        prefixBits,
        'prefixBits',
        'must be between 1 and 8',
      );
    }
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    final prefixLimit = (1 << prefixBits) - 1;
    final firstByte = bytes[offset] & 0xFF;
    var value = firstByte & prefixLimit;
    var newOffset = offset + 1;

    // If the prefix bits are all ones, the remainder follows in continuation
    // bytes (7 bits each, MSB = 1 for more).
    if (value == prefixLimit) {
      var multiplier = 1;
      while (true) {
        if (newOffset >= bytes.length) {
          throw ArgumentError(
            'Incomplete QPACK integer at offset $offset',
          );
        }
        final b = bytes[newOffset] & 0xFF;
        newOffset++;
        value += (b & 0x7F) * multiplier;
        multiplier <<= 7;
        if ((b & 0x80) == 0) break;

        // Guard against runaway / overflow past 62 bits.
        if (multiplier > (1 << 56)) {
          throw ArgumentError('QPACK integer too large');
        }
      }
    }

    return (value, newOffset);
  }
}

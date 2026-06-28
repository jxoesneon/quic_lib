import 'dart:typed_data';

/// QUIC packet number encoding and reconstruction per RFC 9000 Section 17.1.
///
/// Packet numbers are truncated to the minimum byte length that makes them
/// unambiguous given the largest acknowledged packet number. [encode] performs
/// the truncation, while [reconstruct] recovers the full 62-bit value on the
/// receiving side. [minEncodingLength] computes the smallest safe width.
///
/// ## Example
/// ```dart
/// final pn = 42;
/// final bytes = PacketNumber.encode(pn, 1); // 1 byte
/// final reconstructed = PacketNumber.reconstruct(
///   bytes[0], 8, largestAcked: 0,
/// );
/// ```
///
/// See also:
/// - [PacketNumber.minEncodingLength]
/// - RFC 9000 Section 17.1
class PacketNumber {
  PacketNumber._();

  /// Encode a packet number into exactly [byteLength] bytes (1..4).
  ///
  /// [packetNumber] is the full 62-bit packet number.
  /// [byteLength] must be between 1 and 4 inclusive.
  ///
  /// Throws [ArgumentError] if [byteLength] is outside the 1..4 range.
  static Uint8List encode(int packetNumber, int byteLength) {
    if (byteLength < 1 || byteLength > 4) {
      throw ArgumentError('Packet number byte length must be 1..4');
    }
    final result = Uint8List(byteLength);
    for (var i = byteLength - 1; i >= 0; i--) {
      result[i] = packetNumber & 0xFF;
      packetNumber >>= 8;
    }
    return result;
  }

  /// Reconstruct a full packet number from a truncated encoding.
  ///
  /// [truncated] is the decoded truncated value.
  /// [numBits] is the bit width of the truncated encoding (8, 16, 24, or 32).
  /// [largestAcked] is the largest acknowledged packet number.
  ///
  /// Uses the algorithm from RFC 9000 Section 17.1 to find the unique
  /// candidate in the window around [largestAcked].
  static int reconstruct(int truncated, int numBits, int largestAcked) {
    final window = 1 << numBits;
    final halfWindow = window >> 1;
    final mask = window - 1;

    var candidate = (largestAcked & ~mask) | truncated;

    if (candidate <= largestAcked - halfWindow &&
        candidate < (1 << 62) - window) {
      candidate += window;
    } else if (candidate > largestAcked + halfWindow && candidate >= window) {
      candidate -= window;
    }

    return candidate;
  }

  /// Return the minimum byte length (1..4) needed to encode [packetNumber]
  /// unambiguously given [largestAcked].
  ///
  /// Tries widths from 1 to 4 bytes and returns the first that yields a
  /// reconstructable packet number equal to [packetNumber].
  static int minEncodingLength(int packetNumber, int largestAcked) {
    for (var len = 1; len <= 4; len++) {
      final numBits = len * 8;
      final reconstructed = reconstruct(
          packetNumber & ((1 << numBits) - 1), numBits, largestAcked);
      if (reconstructed == packetNumber) {
        return len;
      }
    }
    return 4;
  }
}

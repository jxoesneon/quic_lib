import 'dart:typed_data';

/// QUIC packet number encoding and reconstruction per RFC 9000 Section 17.1.
class PacketNumber {
  PacketNumber._();

  /// Encode a packet number into exactly [byteLength] bytes (1..4).
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

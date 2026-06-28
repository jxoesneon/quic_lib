import 'dart:math';
import 'dart:typed_data';

/// Implements RFC 9287 greasing of the QUIC bit.
class QuicBitGreaser {
  static final _random = Random.secure();

  /// Returns true approximately 50% of the time.
  static bool shouldGrease() => _random.nextBool();

  /// Sets the QUIC bit (bit 6 of the first byte, 0-indexed from MSB).
  /// The QUIC bit is the second-most-significant bit.
  static Uint8List greasePacket(Uint8List packet) {
    if (packet.isEmpty) return packet;
    final result = Uint8List.fromList(packet);
    result[0] |= 0x40; // Set bit 6 (0x40 = 01000000)
    return result;
  }

  /// Clears the QUIC bit.
  static Uint8List ungreasePacket(Uint8List packet) {
    if (packet.isEmpty) return packet;
    final result = Uint8List.fromList(packet);
    result[0] &= ~0x40; // Clear bit 6
    return result;
  }

  /// Checks if the QUIC bit is set.
  static bool isQuicBitSet(Uint8List packet) {
    if (packet.isEmpty) return false;
    return (packet[0] & 0x40) != 0;
  }

  /// Randomly sets or clears the QUIC bit.
  static Uint8List randomizeQuicBit(Uint8List packet) {
    if (packet.isEmpty) return packet;
    final result = Uint8List.fromList(packet);
    if (shouldGrease()) {
      result[0] |= 0x40;
    } else {
      result[0] &= ~0x40;
    }
    return result;
  }
}

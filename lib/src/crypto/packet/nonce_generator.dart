import 'dart:typed_data';

/// QUIC packet nonce construction per RFC 9001 Section 5.3.
///
/// nonce = iv XOR pad_left(packet_number, 12)
class NonceGenerator {
  /// Build a 12-byte nonce from the IV and packet number.
  ///
  /// [iv] must be exactly 12 bytes.
  /// [packetNumber] is the full reconstructed packet number.
  ///
  /// The packet number is left-padded with zeros to 12 bytes (big-endian)
  /// and XORed with the IV.
  static Uint8List generate(List<int> iv, int packetNumber) {
    if (iv.length != 12) {
      throw ArgumentError.value(iv, 'iv', 'must be exactly 12 bytes');
    }

    final nonce = Uint8List(12);

    // Write packet number as big-endian, left-padded with zeros to 12 bytes.
    var pn = packetNumber;
    for (var i = 11; i >= 0; i--) {
      nonce[i] = pn & 0xFF;
      pn >>= 8;
    }

    // XOR with IV.
    for (var i = 0; i < 12; i++) {
      nonce[i] ^= iv[i];
    }

    return nonce;
  }
}

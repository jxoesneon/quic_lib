import 'dart:typed_data';

/// TLS 1.3 Finished message per RFC 8446 Section 4.4.4.
///
/// The Finished message is the final message in the Authentication Block
/// and is essential for providing authentication of the handshake.
///
/// ```
/// struct {
///     opaque verify_data[Hash.length];
/// } Finished;
/// ```
///
/// The verify_data length depends on the hash algorithm negotiated:
/// - 32 bytes for SHA-256
/// - 48 bytes for SHA-384
///
/// This class only implements the data structure and serializer/parser;
/// no cryptographic operations (HMAC, transcript hash, etc.) are performed.
class FinishedMessage {
  /// The verify_data field. Length = Hash.length (32 for SHA-256, 48 for SHA-384).
  final List<int> verifyData;

  FinishedMessage({required this.verifyData});

  /// Serialize: uint8 array of verify_data field length, followed by verify_data.
  ///
  /// Returns a [Uint8List] containing the raw verify_data bytes.
  /// No length prefix is emitted; the length is implicit per the negotiated hash.
  Uint8List serialize() {
    final buffer = Uint8List(verifyData.length);
    for (var i = 0; i < verifyData.length; i++) {
      buffer[i] = verifyData[i];
    }
    return buffer;
  }

  /// Parse from bytes.
  ///
  /// The entire [bytes] array is consumed as the verify_data field.
  /// Callers are responsible for ensuring the byte length matches the
  /// expected Hash.length for the negotiated cipher suite.
  static FinishedMessage parse(Uint8List bytes) {
    return FinishedMessage(verifyData: bytes.toList());
  }
}

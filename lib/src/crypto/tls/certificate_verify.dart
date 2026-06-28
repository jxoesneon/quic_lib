import 'dart:typed_data';

/// TLS 1.3 CertificateVerify structure per RFC 8446 Section 4.4.3.
///
/// ```
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
/// ```
///
/// This class only implements the data structure and serializer/parser;
/// no cryptographic operations (signature generation or verification) are
/// performed here.
class CertificateVerify {
  // Common signature schemes (RFC 8446 Appendix B.3.1.3).
  static const int rsaPkcs1Sha256 = 0x0401;
  static const int rsaPkcs1Sha384 = 0x0501;
  static const int rsaPssRsaeSha256 = 0x0804;
  static const int rsaPssRsaeSha384 = 0x0805;
  static const int ecdsaSecp256r1Sha256 = 0x0403;
  static const int ecdsaSecp384r1Sha384 = 0x0503;
  static const int ed25519 = 0x0807;

  /// Signature scheme (RFC 8446 Appendix B.3.1.3).
  final int signatureScheme; // e.g., 0x0804 = rsa_pss_rsae_sha256

  /// The digital signature.
  final List<int> signature;

  CertificateVerify({required this.signatureScheme, required this.signature});

  /// Serialize: uint16 scheme + uint16 length + signature bytes
  Uint8List serialize() {
    final sigLength = signature.length;
    final buffer = Uint8List(2 + 2 + sigLength);
    var offset = 0;

    // algorithm (uint16, big-endian)
    buffer[offset++] = (signatureScheme >> 8) & 0xFF;
    buffer[offset++] = signatureScheme & 0xFF;

    // signature length (uint16, big-endian)
    buffer[offset++] = (sigLength >> 8) & 0xFF;
    buffer[offset++] = sigLength & 0xFF;

    // signature bytes
    for (var i = 0; i < sigLength; i++) {
      buffer[offset++] = signature[i];
    }

    return buffer;
  }

  /// Parse from bytes.
  static CertificateVerify parse(Uint8List bytes) {
    if (bytes.length < 4) {
      throw ArgumentError(
        'CertificateVerify requires at least 4 bytes (got ${bytes.length})',
      );
    }

    var offset = 0;

    // algorithm (uint16)
    final signatureScheme = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;

    // signature length (uint16)
    final sigLength = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;

    if (bytes.length < offset + sigLength) {
      throw ArgumentError(
        'CertificateVerify signature length ($sigLength) exceeds available '
        'bytes (${bytes.length - offset})',
      );
    }

    // signature bytes
    final signature = bytes.sublist(offset, offset + sigLength).toList();

    return CertificateVerify(
      signatureScheme: signatureScheme,
      signature: signature,
    );
  }
}

import 'dart:typed_data';

/// Parsed certificate metadata used for chain validation.
///
/// In a full implementation this would be produced by an ASN.1 / X.509 parser.
/// The scaffold stores the raw bytes and synthetic fields so that the
/// validation logic can be wired in later without changing the public API.
class CertificateInfo {
  final List<int> rawBytes;
  final List<int> subjectPublicKey;
  final String algorithm;
  final DateTime notBefore;
  final DateTime notAfter;
  final String subjectName;
  final String issuerName;

  CertificateInfo({
    required this.rawBytes,
    required this.subjectPublicKey,
    required this.algorithm,
    required this.notBefore,
    required this.notAfter,
    required this.subjectName,
    this.issuerName = '',
  });
}

/// Parses a raw certificate into a [CertificateInfo].
///
/// **Scaffold:** Constructs a synthetic [CertificateInfo] from the raw bytes
/// so that chain validation logic can be tested. Real ASN.1 parsing is a
/// future enhancement.
CertificateInfo parseCertificate(List<int> rawBytes) {
  return CertificateInfo(
    rawBytes: Uint8List.fromList(rawBytes),
    subjectPublicKey: const [],
    algorithm: 'ed25519',
    notBefore: DateTime(2020, 1, 1),
    notAfter: DateTime(2030, 1, 1),
    subjectName: 'CN=scaffold',
    issuerName: 'CN=scaffold-issuer',
  );
}

/// Returns `true` if [cert] is outside its validity window relative to [now].
bool isExpired(CertificateInfo cert, DateTime now) {
  return now.isBefore(cert.notBefore) || now.isAfter(cert.notAfter);
}

/// Returns `true` if [cert] is self-signed (subject == issuer).
bool isSelfSigned(CertificateInfo cert) {
  return cert.subjectName == cert.issuerName;
}

/// A chain of certificates ordered from end-entity to root-adjacent.
class CertificateChain {
  final List<CertificateInfo> certs;

  CertificateChain(this.certs);

  /// Validates the chain:
  /// * No expired certificates (relative to [now]).
  /// * No self-signed certificates except at the end.
  /// * Every certificate's algorithm is supported.
  bool validateChain(DateTime now) {
    for (var i = 0; i < certs.length; i++) {
      final cert = certs[i];
      if (isExpired(cert, now)) {
        return false;
      }
      if (i < certs.length - 1 && isSelfSigned(cert)) {
        return false;
      }
      if (cert.algorithm != 'ed25519' &&
          cert.algorithm != 'ecdsaP256' &&
          cert.algorithm != 'rsaPkcs1Sha256' &&
          cert.algorithm != 'rsaPkcs1Sha384') {
        return false;
      }
    }
    return true;
  }
}

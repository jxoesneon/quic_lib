import 'dart:typed_data';

import 'package:dart_quic/src/crypto/tls/x509_parser.dart';

/// Parsed certificate metadata used for chain validation.
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
/// Delegates to [parseX509] to extract fields from DER-encoded X.509 bytes.
/// Throws [FormatException] if [rawBytes] are not valid DER.
CertificateInfo parseCertificate(List<int> rawBytes) {
  final x509 = parseX509(rawBytes);
  return CertificateInfo(
    rawBytes: Uint8List.fromList(rawBytes),
    subjectPublicKey: Uint8List.fromList(x509.subjectPublicKeyInfo),
    algorithm: x509.signatureAlgorithm,
    notBefore: x509.notBefore,
    notAfter: x509.notAfter,
    subjectName: String.fromCharCodes(x509.subject),
    issuerName: String.fromCharCodes(x509.issuer),
  );
}

/// Returns `true` if [cert] is outside its validity window relative to [now].
bool isExpired(CertificateInfo cert, DateTime now) {
  return now.isBefore(cert.notBefore) || now.isAfter(cert.notAfter);
}

/// Returns `true` if [cert] is self-signed (subject == issuer and both are non-empty).
bool isSelfSigned(CertificateInfo cert) {
  return cert.subjectName.isNotEmpty &&
      cert.subjectName == cert.issuerName;
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

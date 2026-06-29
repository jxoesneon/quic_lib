import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:quic_lib/src/libp2p/libp2p_tls_extension.dart';
import 'package:quic_lib/src/libp2p/peer_id.dart';

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
  return cert.subjectName.isNotEmpty && cert.subjectName == cert.issuerName;
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

  /// Extracts the libp2p TLS extension from the end-entity certificate.
  ///
  /// Returns `null` if the extension is not present or cannot be parsed.
  Libp2pExtension? extractLibp2pExtension() {
    if (certs.isEmpty) return null;
    final x509 = parseX509(certs.first.rawBytes);
    return parseLibp2pExtension(x509);
  }

  /// Verifies the libp2p signature in the end-entity certificate and checks
  /// that the derived [PeerId] matches [expectedPeerId].
  ///
  /// This method:
  /// 1. Extracts the [SignedKey] from the libp2p TLS extension.
  /// 2. Reconstructs the signed message as `libp2p-tls-handshake:` ||
  ///    SubjectPublicKeyInfo DER from the end-entity certificate.
  /// 3. Verifies the [SignedKey.signature] against that message using the
  ///    public key from the extension (Ed25519 verification).
  /// 4. Derives the [PeerId] from the public key data.
  /// 5. Compares the derived [PeerId] with [expectedPeerId].
  ///
  /// Returns `true` only if all steps succeed.
  Future<bool> verifyLibp2pSignature(
    PeerId expectedPeerId,
    CryptoBackend backend,
  ) async {
    final ext = extractLibp2pExtension();
    if (ext == null) return false;

    final signedKey = ext.signedKey;
    final publicKeyData = signedKey.publicKey.data;

    // Reconstruct the signed message.
    if (certs.isEmpty) return false;
    final x509 = parseX509(certs.first.rawBytes);
    final spkiDer = x509.subjectPublicKeyInfo;
    final handshakeMessage = Uint8List.fromList([
      ...utf8.encode('libp2p-tls-handshake:'),
      ...spkiDer,
    ]);

    // Verify the signature using the public key in the extension.
    final pubKey = _SimplePublicKey(publicKeyData);
    final signatureValid = await backend.ed25519Verify(
      pubKey,
      handshakeMessage,
      signedKey.signature,
    );
    if (!signatureValid) return false;

    // Derive PeerId from the public key data.
    final derivedPeerId = await PeerId.fromPublicKey(publicKeyData);
    return derivedPeerId == expectedPeerId;
  }
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

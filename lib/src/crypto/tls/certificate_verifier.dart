import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_chain.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';

/// TLS certificate chain verification.
///
/// Performs chain validation including:
/// * ASN.1 / X.509 parsing of [CertificateEntry.certData].
/// * Checking validity dates (NotBefore / NotAfter).
/// * Name chaining (Subject of cert i == Issuer of cert i-1).
/// * Signature verification against issuer public keys.
///
/// Note: CRL/OCSP revocation checks are not implemented in this version.
class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

class CertificateVerifier {
  final CryptoBackend _backend;

  CertificateVerifier(this._backend);

  /// Verifies a certificate chain.
  ///
  /// [chain] is ordered from end-entity (index 0) to the intermediate closest
  /// to the root (index n-1).  The trusted root [trustedRoot] is *not* part
  /// of [chain].
  ///
  /// Returns `true` if every certificate's signature can be verified by the
  /// public key of the next certificate, and the last certificate's signature
  /// can be verified by [trustedRoot].
  Future<bool> verifyCertificateChain(
    List<CertificateMessage> chain,
    PublicKey trustedRoot,
  ) async {
    // SECURITY: An empty chain is never valid — reject immediately.
    if (chain.isEmpty) {
      return false;
    }

    // Parse each raw certificate and build a CertificateChain for validation.
    final infos = <CertificateInfo>[];
    for (final cert in chain) {
      for (final entry in cert.entries) {
        infos.add(parseCertificate(entry.certData));
      }
    }
    final certChain = CertificateChain(infos);
    if (!certChain.validateChain(DateTime.now())) {
      return false;
    }

    for (var i = 0; i < chain.length; i++) {
      final cert = chain[i];

      // Choose the public key that should have signed this certificate.
      final PublicKey issuerKey;
      if (i + 1 < chain.length) {
        final nextCert = chain[i + 1];
        final nextEntry = nextCert.entries.first;
        final nextInfo = parseCertificate(nextEntry.certData);
        issuerKey = _SimplePublicKey(nextInfo.subjectPublicKey);
      } else {
        issuerKey = trustedRoot;
      }

      if (!await _verifyOneCertificate(cert, issuerKey)) {
        return false;
      }
    }

    return true;
  }

  /// Verifies a single [signature] over [message] using [pubKey].
  ///
  /// [algorithm] must be one of:
  /// * `'ed25519'`   – delegates to [CryptoBackend.ed25519Verify]
  /// * `'ecdsaP256'` – delegates to [CryptoBackend.ecdsaP256Verify]
  /// * `'rsaPkcs1Sha256'` – delegates to [CryptoBackend.rsaPkcs1Verify]
  ///   with [Sha256].
  /// * `'rsaPkcs1Sha384'` – delegates to [CryptoBackend.rsaPkcs1Verify]
  ///   with [Sha384].
  ///
  /// Throws [UnsupportedError] for unknown algorithms.
  Future<bool> verifySignature(
    PublicKey pubKey,
    Uint8List message,
    Uint8List signature, {
    String algorithm = 'ed25519',
  }) async {
    switch (algorithm) {
      case 'ed25519':
        return _backend.ed25519Verify(pubKey, message, signature);
      case 'ecdsaP256':
        return _backend.ecdsaP256Verify(pubKey, message, signature);
      case 'rsaPkcs1Sha256':
        return _backend.rsaPkcs1Verify(pubKey, Sha256(), message, signature);
      case 'rsaPkcs1Sha384':
        return _backend.rsaPkcs1Verify(pubKey, Sha384(), message, signature);
      default:
        throw UnsupportedError('Unknown signature algorithm: $algorithm');
    }
  }

  /// Verifies each entry in [cert] using [issuerKey].
  ///
  /// Parses the entry's certData as X.509 and delegates signature
  /// verification to [verifyX509Signature].
  Future<bool> _verifyOneCertificate(
      CertificateMessage cert, PublicKey issuerKey) async {
    for (final entry in cert.entries) {
      final x509 = parseX509(entry.certData);
      if (!await verifyX509Signature(x509, issuerKey, _backend)) {
        return false;
      }
    }
    return true;
  }
}

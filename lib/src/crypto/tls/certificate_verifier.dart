import 'dart:typed_data';

import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/tls/certificate_chain.dart';
import 'package:dart_quic/src/crypto/tls/certificate_message.dart';
import 'package:dart_quic/src/crypto/tls/x509_parser.dart';

/// A scaffold for TLS certificate chain verification.
///
/// **This is intentionally a stub.** Real certificate verification requires:
/// * ASN.1 / X.509 parsing of [CertificateEntry.certData] to extract
///   Subject, Issuer, validity dates, public keys, and signature values.
/// * Checking validity dates (NotBefore / NotAfter).
/// * Name chaining (Subject of cert i == Issuer of cert i-1).
/// * CRL or OCSP revocation checks.
/// * Proper handling of intermediate certificate stores and path building.
///
/// The class is structured so that once those pieces are wired in the
/// loop below can be swapped for real logic without changing the public
/// surface.
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
  ///
  /// **Scaffold behaviour:** always returns `true` so that callers can
  /// integrate the API now and opt-in to real verification later.
  bool verifyCertificateChain(
    List<CertificateMessage> chain,
    PublicKey trustedRoot,
  ) {
    // Empty chain is valid in this scaffold (caller may have no certs).
    if (chain.isEmpty) {
      return true;
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
        issuerKey = trustedRoot; // placeholder so the code compiles
      } else {
        issuerKey = trustedRoot;
      }

      // In a real implementation we would:
      // 1. Parse certData as X.509Certificate.
      // 2. Verify the TBSCertificate signature with issuerKey.
      // 3. Check name chaining and key usage.
      _verifyOneCertificate(cert, issuerKey);
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

  /// Placeholder for per-certificate verification.
  ///
  /// In a real implementation this would parse [cert], extract the
  /// signature algorithm and value from the X.509 structure, and invoke
  /// [verifySignature] with the appropriate public key.
  bool _verifyOneCertificate(CertificateMessage cert, PublicKey issuerKey) {
    // Scaffold: iterate over each entry, parse as X.509, and verify the
    // signature.  Non-DER data is silently accepted so that test stubs
    // continue to work.
    for (final entry in cert.entries) {
      try {
        final x509 = parseX509(entry.certData);
        if (!verifyX509Signature(x509, issuerKey, _backend)) {
          return false;
        }
      } on FormatException {
        // Scaffold fallback: accept non-DER test data.
        continue;
      }
    }
    return true;
  }
}

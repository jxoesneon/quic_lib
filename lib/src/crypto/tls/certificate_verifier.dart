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

/// Verifies X.509 certificate chains during the TLS 1.3 handshake (RFC 8446 Section 4.4.2).
///
/// [CertificateVerifier] performs end-to-end validation of a peer's certificate chain,
/// including ASN.1 parsing, validity-date checking, name chaining, and signature
/// verification against issuer public keys. It is used by the [HandshakeStateMachine]
/// once the [CertificateMessage] and [CertificateVerify] messages have been received.
///
/// Callers typically instantiate this class once per connection and invoke
/// [verifyCertificateChain] when the handshake reaches the certificate-validation stage.
///
/// ## Example
/// ```dart
/// final verifier = CertificateVerifier(cryptoBackend);
/// final valid = await verifier.verifyCertificateChain(chain, trustedRoot);
/// ```
///
/// See also:
/// - [CertificateMessage] — the TLS message carrying the raw certificate chain.
/// - [HandshakeStateMachine] — drives the handshake phases that lead to verification.
/// - RFC 8446 Section 4.4.2 — Certificate message structure.
class CertificateVerifier {
  final CryptoBackend _backend;

  /// Creates a [CertificateVerifier] backed by the given [CryptoBackend].
  ///
  /// The crypto backend provides Ed25519, ECDSA P-256, and RSA signature
  /// verification routines required by [verifySignature].
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

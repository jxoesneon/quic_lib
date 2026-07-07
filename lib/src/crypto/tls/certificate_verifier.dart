import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_chain.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/crl_fetcher.dart';
import 'package:quic_lib/src/crypto/tls/ocsp_fetcher.dart';
import 'package:quic_lib/src/crypto/tls/revocation_policy.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';

/// TLS certificate chain verification.
///
/// Performs chain validation including:
/// * ASN.1 / X.509 parsing of [CertificateEntry.certData].
/// * Checking validity dates (NotBefore / NotAfter).
/// * Name chaining (Subject of cert i == Issuer of cert i-1).
/// * Signature verification against issuer public keys.
/// * Revocation checking via OCSP and CRL when [revocationPolicy] is
///   [RevocationPolicy.softFail] or [RevocationPolicy.hardFail].
///
///
/// Phase 2: OCSP/CRL fetching and validation is performed when the policy is
/// not [RevocationPolicy.disabled]. See [RevocationPolicy] for the failure
/// semantics of each mode.
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
  final RevocationPolicy _revocationPolicy;
  final OcspFetcher _ocspFetcher;
  final CrlFetcher _crlFetcher;

  /// Creates a [CertificateVerifier] backed by the given [CryptoBackend].
  ///
  /// The crypto backend provides Ed25519, ECDSA P-256, and RSA signature
  /// verification routines required by [verifySignature].
  ///
  /// [revocationPolicy] controls how CRL/OCSP revocation checks are handled:
  /// * [RevocationPolicy.disabled] (not the default) skips revocation entirely.
  /// * [RevocationPolicy.softFail] (default) performs OCSP/CRL checks when
  ///   revocation URLs are present. A definitive `revoked` verdict fails the
  ///   chain, but a network/parse error or `unknown` verdict does not.
  /// * [RevocationPolicy.hardFail] performs OCSP/CRL checks and treats any
  ///   failure to obtain a definitive `good` verdict (network error, parse
  ///   error, `unknown`, or missing URLs when URLs were expected) as fatal.
  ///
  /// [ocspFetcher] and [crlFetcher] allow callers to inject custom fetchers
  /// (e.g. with a pre-configured [HttpClient] or a mock for testing). When
  /// omitted, default fetchers are created lazily for each verification.
  CertificateVerifier(
    this._backend, {
    RevocationPolicy revocationPolicy = RevocationPolicy.softFail,
    OcspFetcher? ocspFetcher,
    CrlFetcher? crlFetcher,
  })  : _revocationPolicy = revocationPolicy,
        _ocspFetcher = ocspFetcher ?? OcspFetcher(),
        _crlFetcher = crlFetcher ?? CrlFetcher();

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

    // Phase 2: perform OCSP/CRL revocation checks when the policy is not
    // disabled. For each certificate in the chain, attempt OCSP first (using
    // the next certificate as the issuer for CertID construction) and fall
    // back to CRL. A definitive `revoked` verdict always fails the chain.
    // Under hardFail, any inability to obtain a definitive verdict (network
    // error, parse error, unknown, or missing URLs) is fatal.
    if (_revocationPolicy != RevocationPolicy.disabled) {
      for (var i = 0; i < infos.length; i++) {
        final info = infos[i];
        if (info.revocationInfo.isEmpty) {
          if (_revocationPolicy == RevocationPolicy.hardFail) {
            return false;
          }
          continue;
        }

        // The issuer is the next certificate in the chain (parsed above), or
        // the trusted root for the last certificate. For the root-adjacent
        // cert we only have the trusted public key, so we cannot build a
        // CertID; CRL still works because it only needs the serial number.
        final issuerInfo = (i + 1 < infos.length) ? infos[i + 1] : null;

        final verdict = await _checkRevocation(info, issuerInfo);
        if (verdict == _RevocationVerdict.revoked) {
          return false;
        }
        if (verdict == _RevocationVerdict.unknown &&
            _revocationPolicy == RevocationPolicy.hardFail) {
          return false;
        }
      }
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

  /// Attempts to determine the revocation status of [info] using OCSP (when an
  /// issuer [CertificateInfo] is available to build the CertID) and CRL.
  ///
  /// Returns [_RevocationVerdict.revoked] if either source definitively marks
  /// the certificate as revoked. Returns [_RevocationVerdict.good] if OCSP
  /// reports `good`. Returns [_RevocationVerdict.unknown] if no definitive
  /// verdict could be obtained (network/parse error, OCSP `unknown`, or no
  /// URLs reachable).
  Future<_RevocationVerdict> _checkRevocation(
    CertificateInfo info,
    CertificateInfo? issuerInfo,
  ) async {
    // Try OCSP first when we have an issuer to build the CertID.
    if (issuerInfo != null && info.revocationInfo.ocspUrls.isNotEmpty) {
      final verdict = await _tryOcsp(info, issuerInfo);
      if (verdict != null) {
        return verdict;
      }
    }

    // Fall back to CRL.
    if (info.revocationInfo.crlUrls.isNotEmpty) {
      final crlResult = await _tryCrl(info);
      if (crlResult == true) return _RevocationVerdict.revoked;
      if (crlResult == false) return _RevocationVerdict.good;
      // CRL could not be fetched/parsed — unknown.
    }

    return _RevocationVerdict.unknown;
  }

  /// Attempts an OCSP query for [info] using [issuerInfo] as the issuer.
  ///
  /// Returns `null` if the query could not be performed or parsed (caller
  /// should fall back to CRL). Returns a [_RevocationVerdict] otherwise.
  Future<_RevocationVerdict?> _tryOcsp(
    CertificateInfo info,
    CertificateInfo issuerInfo,
  ) async {
    try {
      final issuerX509 = parseX509(issuerInfo.rawBytes);
      final issuerNameHash = sha1Digest(Uint8List.fromList(issuerX509.issuer));
      final issuerKeyBits = extractSubjectPublicKeyBitString(
        issuerX509.subjectPublicKeyInfo,
      );
      final issuerKeyHash = sha1Digest(Uint8List.fromList(issuerKeyBits));
      final request = buildOcspRequest(
        issuerNameHash: issuerNameHash,
        issuerKeyHash: issuerKeyHash,
        serialNumber: Uint8List.fromList(info.serialNumber),
      );
      for (final url in info.revocationInfo.ocspUrls) {
        try {
          final verdict = await _ocspFetcher.fetch(url, request);
          switch (verdict.status) {
            case OcspCertStatus.good:
              return _RevocationVerdict.good;
            case OcspCertStatus.revoked:
              return _RevocationVerdict.revoked;
            case OcspCertStatus.unknown:
              continue;
          }
        } catch (_) {
          // Try the next OCSP URL, then fall back to CRL.
        }
      }
    } catch (_) {
      // CertID construction or issuer parse failure — fall back to CRL.
    }
    return null;
  }

  /// Attempts a CRL fetch for [info] across all distribution-point URLs.
  ///
  /// Returns `true` if any CRL lists the certificate's serial as revoked.
  /// Returns `false` if a CRL was successfully fetched and the serial is not
  /// listed. Returns `null` if no CRL could be fetched or parsed.
  Future<bool?> _tryCrl(CertificateInfo info) async {
    for (final url in info.revocationInfo.crlUrls) {
      try {
        return await _crlFetcher.fetch(url, info.serialNumber);
      } catch (_) {
        // Try the next CRL URL.
      }
    }
    return null;
  }
}

/// Internal tri-state verdict for a single certificate's revocation check.
enum _RevocationVerdict {
  /// The certificate is confirmed not revoked.
  good,

  /// The certificate is confirmed revoked.
  revoked,

  /// No definitive verdict could be obtained.
  unknown,
}

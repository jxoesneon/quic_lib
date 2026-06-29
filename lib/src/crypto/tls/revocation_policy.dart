/// Policy controlling how certificate revocation is handled during chain
/// verification.
///
/// Phase 1 of revocation support (v1.9.0) only parses CRL and OCSP URLs from
/// X.509 extensions. Full fetching and validation of revocation data is
/// planned for a later release.
enum RevocationPolicy {
  /// Revocation extension parsing is skipped entirely.
  disabled,

  /// Revocation URLs are extracted from the certificate and exposed to
  /// callers, but the verifier does not fail when a check cannot be performed.
  ///
  /// This is the default and safest Phase 1 policy: it surfaces the data
  /// without blocking handshakes while the revocation backend is still being
  /// implemented.
  softFail,

  /// Revocation failures are fatal. This policy requires a full CRL/OCSP
  /// implementation and is reserved for future releases.
  hardFail,
}

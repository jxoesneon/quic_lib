import 'cipher_suites.dart';
import 'crypto_backend.dart';
import '../wire/quic_versions.dart';

/// A simple in-memory [SecretKey] implementation.
class SimpleSecretKey implements SecretKey {
  final List<int> _bytes;

  /// Creates an in-memory secret key wrapping the raw [bytes].
  SimpleSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

/// QUIC Initial Secret derivation per RFC 9001 Section 5.2.
///
/// QUIC version 1 and version 2 (RFC 9369) use *different* fixed initial
/// salts when deriving Initial keys. Pass the negotiated [version] to
/// [derive] so that the correct salt is selected; the default is
/// [QuicVersions.v1] for backward compatibility.
///
/// See also:
/// - [initialSalt] — QUIC v1 salt (RFC 9001 §5.2)
/// - [v2InitialSalt] — QUIC v2 salt (RFC 9369 §3.3.1)
/// - [QuicVersions] — version constants
class InitialSecrets {
  /// Creates an Initial secrets helper (all methods are static).
  InitialSecrets();

  /// QUIC v1 fixed initial salt (RFC 9001 Section 5.2).
  static final List<int> initialSalt = [
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
  ];

  /// QUIC v2 fixed initial salt (RFC 9369 Section 3.3.1).
  ///
  /// This is the first 20 bytes of the SHA-256 digest of `"QUICv2 salt"`.
  /// QUIC v2 connections MUST use this salt instead of [initialSalt] when
  /// deriving Initial packet-protection keys, otherwise the derived keys
  /// will not match the peer's.
  static final List<int> v2InitialSalt = [
    0x0d,
    0xed,
    0xe3,
    0xde,
    0xf7,
    0x00,
    0xa6,
    0xdb,
    0x81,
    0x93,
    0x81,
    0xbe,
    0x6e,
    0x26,
    0x9d,
    0xcb,
    0xf9,
    0xbd,
    0x2e,
    0xd9,
  ];

  /// Returns the initial salt appropriate for [version].
  ///
  /// Uses [v2InitialSalt] for [QuicVersions.v2] and [initialSalt] for all
  /// other versions (including [QuicVersions.v1]).
  static List<int> saltForVersion(int version) {
    if (version == QuicVersions.v2) {
      return v2InitialSalt;
    }
    return initialSalt;
  }

  /// Derive client and server initial secrets from the destination
  /// connection ID.
  ///
  /// [version] selects the fixed initial salt used for HKDF-Extract.
  /// It defaults to [QuicVersions.v1] for backward compatibility; pass
  /// [QuicVersions.v2] for QUIC version 2 connections (RFC 9369) so that
  /// the v2-specific salt ([v2InitialSalt]) is used.
  ///
  /// The "client in" and "server in" HKDF-Expand-Label labels are the same
  /// for both versions; only the salt differs.
  static Future<({SecretKey clientSecret, SecretKey serverSecret})> derive(
    List<int> destinationConnectionId, {
    required CryptoBackend backend,
    int version = QuicVersions.v1,
  }) async {
    final salt = SimpleSecretKey(List<int>.from(saltForVersion(version)));
    final ikm = SimpleSecretKey(List<int>.from(destinationConnectionId));

    final initialSecret = await backend.hkdfExtract(Sha256(), salt, ikm);

    final clientBytes = await backend.hkdfExpandLabel(
      Sha256(),
      initialSecret,
      'client in',
      <int>[],
      32,
    );

    final serverBytes = await backend.hkdfExpandLabel(
      Sha256(),
      initialSecret,
      'server in',
      <int>[],
      32,
    );

    return (
      clientSecret: SimpleSecretKey(clientBytes),
      serverSecret: SimpleSecretKey(serverBytes),
    );
  }
}

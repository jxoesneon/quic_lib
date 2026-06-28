import 'cipher_suites.dart';
import 'crypto_backend.dart';

/// A simple in-memory [SecretKey] implementation.
class SimpleSecretKey implements SecretKey {
  final List<int> _bytes;

  SimpleSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

/// QUIC Initial Secret derivation per RFC 9001 Section 5.2.
class InitialSecrets {
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

  /// Derive client and server initial secrets from the destination connection ID.
  static Future<({SecretKey clientSecret, SecretKey serverSecret})> derive(
    List<int> destinationConnectionId, {
    required CryptoBackend backend,
  }) async {
    final salt = SimpleSecretKey(List<int>.from(initialSalt));
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

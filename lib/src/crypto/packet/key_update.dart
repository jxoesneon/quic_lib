import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';

/// QUIC Key Update derivation per RFC 9001 Section 6.
class KeyUpdate {
  /// Derive the next-generation application traffic secret.
  ///
  /// application_traffic_secret_N+1 = HKDF-Expand-Label(
  ///   secret, "quic ku", "", Hash.length)
  static Future<SecretKey> deriveNextSecret({
    required SecretKey currentSecret,
    required CryptoBackend backend,
  }) async {
    final hash = Sha256();
    final nextSecretBytes = await backend.hkdfExpandLabel(
      hash,
      currentSecret,
      'quic ku',
      <int>[],
      hash.hashLength,
    );
    return SimpleSecretKey(nextSecretBytes);
  }
}

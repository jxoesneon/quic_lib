import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';

/// QUIC key derivation from a traffic secret per RFC 9001 Section 5.1.
///
/// Derives the packet protection key, IV, and header-protection key using
/// HKDF-Expand-Label with the cipher-suite's hash algorithm.  This
/// implementation uses SHA-256 (the hash for TLS_AES_128_GCM_SHA256, the
/// mandatory QUIC cipher suite).
class KeyDerivation {
  /// Derive key, IV, and header protection key from a traffic secret.
  ///
  /// Uses HKDF-Expand-Label per RFC 9001 §5.1:
  ///   key = HKDF-Expand-Label(secret, "quic key", "", key_length)
  ///   iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
  ///   hp  = HKDF-Expand-Label(secret, "quic hp",  "", hp_key_length)
  static Future<({List<int> key, List<int> iv, List<int> hpKey})> deriveKeys({
    required SecretKey secret,
    required int keyLength,
    required int hpKeyLength,
    required CryptoBackend backend,
  }) async {
    final hash = Sha256();

    final key = await backend.hkdfExpandLabel(
      hash,
      secret,
      'quic key',
      <int>[],
      keyLength,
    );

    final iv = await backend.hkdfExpandLabel(
      hash,
      secret,
      'quic iv',
      <int>[],
      12,
    );

    final hpKey = await backend.hkdfExpandLabel(
      hash,
      secret,
      'quic hp',
      <int>[],
      hpKeyLength,
    );

    return (key: key, iv: iv, hpKey: hpKey);
  }
}

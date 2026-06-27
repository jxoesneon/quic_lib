import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';

/// 0-RTT helper for QUIC.
///
/// Provides key derivation from a PSK and transport-parameter checks
/// per RFC 9001 Section 4.6 / RFC 8446.
class ZeroRttHelper {
  /// Derive 0-RTT keys from a PSK (pre-shared key).
  ///
  /// Uses HKDF-Expand-Label with "quic key", "quic iv", and "quic hp"
  /// labels per RFC 9001 Section 5.1.
  static Future<({List<int> key, List<int> iv, List<int> hpKey})> deriveKeys({
    required SecretKey psk,
    required int keyLength,
    required int hpKeyLength,
    required CryptoBackend backend,
  }) async {
    final hash = Sha256();

    final key = await backend.hkdfExpandLabel(
      hash,
      psk,
      'quic key',
      <int>[],
      keyLength,
    );

    final iv = await backend.hkdfExpandLabel(
      hash,
      psk,
      'quic iv',
      <int>[],
      12,
    );

    final hpKey = await backend.hkdfExpandLabel(
      hash,
      psk,
      'quic hp',
      <int>[],
      hpKeyLength,
    );

    return (key: key, iv: iv, hpKey: hpKey);
  }

  /// Check if 0-RTT is acceptable based on transport params (max_early_data > 0).
  static bool isAcceptable(int maxEarlyData) => maxEarlyData > 0;

  /// Default max_early_data size (0xFFFFFFFF = unlimited per RFC 8446).
  static const int defaultMaxEarlyData = 0xFFFFFFFF;
}

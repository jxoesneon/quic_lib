import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/wire/quic_versions.dart';

/// QUIC Retry Integrity Tag computation and verification per RFC 9001 §5.8.
///
/// QUIC version 1 (RFC 9001) and version 2 (RFC 9369 §3.3.3) use *different*
/// fixed AES-128-GCM key/nonce pairs for the Retry integrity tag. Pass the
/// negotiated [version] to [compute] and [verify] so that the correct
/// key/nonce is selected; the default is [QuicVersions.v1] for backward
/// compatibility.
///
/// See also:
/// - [retryKey] / [retryNonce] — QUIC v1 key and nonce (RFC 9001 §5.8)
/// - [v2RetryKey] / [v2RetryNonce] — QUIC v2 key and nonce (RFC 9369 §3.3.3)
/// - [QuicVersions] — version constants
class RetryIntegrityTag {
  /// Creates a Retry integrity tag helper (all methods are static).
  RetryIntegrityTag();

  /// QUIC v1 retry integrity key (RFC 9001 §5.8).
  static const List<int> retryKey = [
    0xbe,
    0x0c,
    0x69,
    0x0b,
    0x9f,
    0x66,
    0x57,
    0x5a,
    0x1d,
    0x76,
    0x6b,
    0x54,
    0xe3,
    0x68,
    0xc8,
    0x4e,
  ];

  /// QUIC v1 retry integrity nonce (RFC 9001 §5.8).
  static const List<int> retryNonce = [
    0x46,
    0x15,
    0x99,
    0xd3,
    0x5d,
    0x63,
    0x2b,
    0xf2,
    0x23,
    0x98,
    0x25,
    0xbb,
  ];

  /// QUIC v2 retry integrity key (RFC 9369 §3.3.3).
  ///
  /// Derived from the SHA-256 of `"QUICv2 retry secret"` using the
  /// `"quicv2 key"` HKDF-Expand-Label.
  static const List<int> v2RetryKey = [
    0x8f,
    0xb4,
    0xb0,
    0x1b,
    0x56,
    0xac,
    0x48,
    0xe2,
    0x60,
    0xfb,
    0xcb,
    0xce,
    0xad,
    0x7c,
    0xcc,
    0x92,
  ];

  /// QUIC v2 retry integrity nonce (RFC 9369 §3.3.3).
  ///
  /// Derived from the SHA-256 of `"QUICv2 retry secret"` using the
  /// `"quicv2 iv"` HKDF-Expand-Label.
  static const List<int> v2RetryNonce = [
    0xd8,
    0x69,
    0x69,
    0xbc,
    0x2d,
    0x7c,
    0x6d,
    0x99,
    0x90,
    0xef,
    0xb0,
    0x4a,
  ];

  /// Returns the retry integrity key for [version].
  ///
  /// Uses [v2RetryKey] for [QuicVersions.v2] and [retryKey] otherwise.
  static List<int> keyForVersion(int version) {
    if (version == QuicVersions.v2) {
      return v2RetryKey;
    }
    return retryKey;
  }

  /// Returns the retry integrity nonce for [version].
  ///
  /// Uses [v2RetryNonce] for [QuicVersions.v2] and [retryNonce] otherwise.
  static List<int> nonceForVersion(int version) {
    if (version == QuicVersions.v2) {
      return v2RetryNonce;
    }
    return retryNonce;
  }

  /// Build the pseudo-retry associated data.
  static Uint8List _buildPseudoRetry(
    List<int> originalDestinationConnectionId,
    Uint8List retryPacketWithoutTag,
  ) {
    final pseudoRetry = Uint8List(
      1 + originalDestinationConnectionId.length + retryPacketWithoutTag.length,
    );
    pseudoRetry[0] = originalDestinationConnectionId.length;
    pseudoRetry.setAll(1, originalDestinationConnectionId);
    pseudoRetry.setAll(
        1 + originalDestinationConnectionId.length, retryPacketWithoutTag);
    return pseudoRetry;
  }

  /// Compute the retry integrity tag for a Retry packet.
  ///
  /// pseudo_retry = original_dcid_length || original_dcid || retry_packet_without_tag
  /// tag = AES-128-GCM-Encrypt(retry_key, retry_nonce, pseudo_retry, "")
  ///
  /// [version] selects the fixed key/nonce pair. It defaults to
  /// [QuicVersions.v1] for backward compatibility; pass [QuicVersions.v2]
  /// for QUIC version 2 Retry packets (RFC 9369 §3.3.3).
  static Future<Uint8List> compute({
    required List<int> originalDestinationConnectionId,
    required Uint8List retryPacketWithoutTag,
    required CryptoBackend backend,
    int version = QuicVersions.v1,
  }) async {
    final pseudoRetry = _buildPseudoRetry(
      originalDestinationConnectionId,
      retryPacketWithoutTag,
    );

    final result = await backend.aeadEncrypt(
      Aes128Gcm(),
      SimpleSecretKey(List<int>.from(keyForVersion(version))),
      List<int>.from(nonceForVersion(version)),
      <int>[], // empty plaintext
      associatedData: pseudoRetry,
    );

    // With empty plaintext the tag is the only output.
    return Uint8List.fromList(result.tag);
  }

  /// Verify the retry integrity tag.
  ///
  /// The [retryPacket] must include the 16-byte tag appended at the end.
  ///
  /// [version] selects the fixed key/nonce pair. It defaults to
  /// [QuicVersions.v1] for backward compatibility; pass [QuicVersions.v2]
  /// for QUIC version 2 Retry packets (RFC 9369 §3.3.3).
  static Future<bool> verify({
    required List<int> originalDestinationConnectionId,
    required Uint8List retryPacket,
    required CryptoBackend backend,
    int version = QuicVersions.v1,
  }) async {
    // SECURITY: Avoid timing side channel by ensuring all error paths go
    // through the same catch block. Do NOT use an early-return for short
    // packets; instead let sublist/crypto fail naturally.
    try {
      final retryPacketWithoutTag = retryPacket.sublist(
        0,
        retryPacket.length - 16,
      );
      final tag = retryPacket.sublist(retryPacket.length - 16);

      final pseudoRetry = _buildPseudoRetry(
        originalDestinationConnectionId,
        Uint8List.fromList(retryPacketWithoutTag),
      );

      await backend.aeadDecrypt(
        Aes128Gcm(),
        SimpleSecretKey(List<int>.from(keyForVersion(version))),
        List<int>.from(nonceForVersion(version)),
        tag,
        associatedData: pseudoRetry,
      );
      return true;
    } catch (_) {
      return false;
    }
  }
}

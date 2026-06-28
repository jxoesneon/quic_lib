import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';

/// QUIC Retry Integrity Tag computation and verification per RFC 9001 §5.8.
class RetryIntegrityTag {
  /// QUIC v1 retry integrity key and nonce (RFC 9001 §5.8).
  static final List<int> retryKey = [
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
  static final List<int> retryNonce = [
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
  static Future<Uint8List> compute({
    required List<int> originalDestinationConnectionId,
    required Uint8List retryPacketWithoutTag,
    required CryptoBackend backend,
  }) async {
    final pseudoRetry = _buildPseudoRetry(
      originalDestinationConnectionId,
      retryPacketWithoutTag,
    );

    final result = await backend.aeadEncrypt(
      Aes128Gcm(),
      SimpleSecretKey(List<int>.from(retryKey)),
      List<int>.from(retryNonce),
      <int>[], // empty plaintext
      associatedData: pseudoRetry,
    );

    // With empty plaintext the tag is the only output.
    return Uint8List.fromList(result.tag);
  }

  /// Verify the retry integrity tag.
  ///
  /// The [retryPacket] must include the 16-byte tag appended at the end.
  static Future<bool> verify({
    required List<int> originalDestinationConnectionId,
    required Uint8List retryPacket,
    required CryptoBackend backend,
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
        SimpleSecretKey(List<int>.from(retryKey)),
        List<int>.from(retryNonce),
        tag,
        associatedData: pseudoRetry,
      );
      return true;
    } catch (_) {
      return false;
    }
  }
}

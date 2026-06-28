import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';

/// QUIC Packet Protection (AEAD encrypt/decrypt).
///
/// Implements RFC 9001 Section 5.3 nonce construction:
///   nonce = iv XOR pad_left(packet_number, 12)
class PacketProtector {
  final CryptoBackend _backend;
  final AeadAlgorithm _aead;
  final SecretKey _key;
  final List<int> _iv;

  PacketProtector({
    required CryptoBackend backend,
    required AeadAlgorithm aead,
    required SecretKey key,
    required List<int> iv,
  })  : _backend = backend,
        _aead = aead,
        _key = key,
        _iv = iv {
    if (_iv.length != _aead.nonceLength) {
      throw ArgumentError(
        'IV length (${_iv.length}) must match AEAD nonce length (${_aead.nonceLength})',
      );
    }
  }

  /// Encrypt a QUIC packet payload.
  ///
  /// [packetNumber] is the full reconstructed packet number.
  /// [headerBytes] is the authenticated additional data (up to and including PN).
  /// [payload] is the plaintext frames.
  /// Returns ciphertext including the authentication tag.
  Future<Uint8List> encrypt(
    int packetNumber,
    Uint8List headerBytes,
    Uint8List payload,
  ) async {
    final nonce = _computeNonce(packetNumber);
    final result = await _backend.aeadEncrypt(
      _aead,
      _key,
      nonce,
      payload,
      associatedData: headerBytes,
    );
    return Uint8List.fromList(result.ciphertext);
  }

  /// Decrypt a QUIC packet payload.
  ///
  /// [packetNumber] is the full reconstructed packet number.
  /// [headerBytes] is the AAD.
  /// [ciphertext] includes the authentication tag.
  /// Returns plaintext or throws if authentication fails.
  Future<Uint8List> decrypt(
    int packetNumber,
    Uint8List headerBytes,
    Uint8List ciphertext,
  ) async {
    final nonce = _computeNonce(packetNumber);
    final plaintext = await _backend.aeadDecrypt(
      _aead,
      _key,
      nonce,
      ciphertext,
      associatedData: headerBytes,
    );
    return Uint8List.fromList(plaintext);
  }

  /// Computes the AEAD nonce as iv XOR left-padded packet number.
  Uint8List _computeNonce(int packetNumber) {
    final paddedPn = Uint8List(_aead.nonceLength);
    // Write packet number into the last bytes (big-endian, left-padded with zeros).
    for (var i = 0; i < 8 && (11 - i) >= 0; i++) {
      paddedPn[11 - i] = (packetNumber >> (8 * i)) & 0xFF;
    }

    final nonce = Uint8List(_aead.nonceLength);
    for (var i = 0; i < _aead.nonceLength; i++) {
      nonce[i] = _iv[i] ^ paddedPn[i];
    }
    return nonce;
  }
}

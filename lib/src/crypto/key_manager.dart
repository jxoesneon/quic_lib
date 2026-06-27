import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/crypto/packet/key_derivation.dart';
import 'package:dart_quic/src/crypto/zero_rtt_helper.dart';
import 'package:dart_quic/src/crypto/packet/header_protection.dart';
import 'package:dart_quic/src/crypto/packet/packet_protector.dart';
import 'package:dart_quic/src/crypto/packet/space_keys.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';

// Re-export for test convenience.
export 'initial_secrets.dart' show SimpleSecretKey;

/// Derives and manages packet protection keys for all QUIC packet number spaces.
///
/// Per RFC 9001, each space has independent keys:
/// - Initial keys: derived from DCID using the fixed initial salt
/// - Handshake keys: derived from the TLS handshake traffic secret
/// - Application keys: derived from the TLS application traffic secret
///
/// **Status:** Initial-space derivation is complete. Handshake and Application
/// key transitions are scaffolded for future TLS integration.
class KeyManager {
  final Map<PacketNumberSpace, PacketNumberSpaceKeys> _keys = {};

  KeyManager._();

  /// Create a [KeyManager] with pre-derived keys for testing.
  KeyManager.forTest();

  /// Derive Initial-space keys from the destination connection ID.
  static Future<KeyManager> deriveInitial(
    List<int> destinationConnectionId,
    CryptoBackend backend,
  ) async {
    final manager = KeyManager._();
    final secrets = await InitialSecrets.derive(
      destinationConnectionId,
      backend: backend,
    );

    // For Initial packets we use AES-128-GCM (mandatory QUIC cipher suite).
    final aead = Aes128Gcm();
    final keyLength = aead.keyLength; // 16 bytes
    final hpKeyLength = 16; // AES-128 header protection key

    // Derive client keys (for sending) and server keys (for receiving).
    // In a real implementation, the role determines which key to use for
    // encrypt vs decrypt. For the pipeline scaffold, we use client keys.
    final clientKeys = await KeyDerivation.deriveKeys(
      secret: secrets.clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    // Store keys for the Initial space.
    // In a full implementation, client/server directionality is tracked
    // separately. Here we store one set for the pipeline to use.
    manager._keys[PacketNumberSpace.initial] = PacketNumberSpaceKeys(
      protector: PacketProtector(
        backend: backend,
        aead: aead,
        key: SimpleSecretKey(clientKeys.key),
        iv: clientKeys.iv,
      ),
      headerProtection: HeaderProtection(
        hpKey: clientKeys.hpKey,
        isChaCha20: false,
      ),
    );

    return manager;
  }

  /// Get the keys for a packet number space, or null if not yet derived.
  PacketNumberSpaceKeys? keysFor(PacketNumberSpace space) => _keys[space];

  /// Install keys for a packet number space (used for Handshake/App transitions).
  void installKeys(
    PacketNumberSpace space,
    PacketNumberSpaceKeys keys,
  ) {
    _keys[space] = keys;
  }

  /// True if keys exist for the given space.
  bool hasKeysFor(PacketNumberSpace space) => _keys.containsKey(space);

  /// Derive Handshake-space keys from the TLS handshake traffic secrets.
  ///
  /// Uses AES-256-GCM (TLS_AES_256_GCM_SHA384) per RFC 9001 Section 5.1.
  /// The AEAD key is 32 bytes and the header-protection key is 16 bytes.
  ///
  /// Per RFC 9001 §4.1.4, endpoints MUST discard Initial keys once
  /// Handshake keys are available.
  static Future<KeyManager> deriveHandshake(
    SecretKey clientSecret,
    SecretKey serverSecret,
    CryptoBackend backend,
  ) async {
    final manager = KeyManager._();
    final aead = Aes256Gcm();
    final keyLength = aead.keyLength; // 32 bytes
    const hpKeyLength = 16; // AES-256 header protection key

    // In a full implementation, client/server directionality is tracked
    // separately. Here we use client keys for the pipeline scaffold.
    final clientKeys = await KeyDerivation.deriveKeys(
      secret: clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.handshake] = PacketNumberSpaceKeys(
      protector: PacketProtector(
        backend: backend,
        aead: aead,
        key: SimpleSecretKey(clientKeys.key),
        iv: clientKeys.iv,
      ),
      headerProtection: HeaderProtection(
        hpKey: clientKeys.hpKey,
        isChaCha20: false,
      ),
    );

    return manager;
  }

  /// Derive Application-space keys from the TLS application traffic secrets.
  ///
  /// Uses AES-128-GCM (TLS_AES_128_GCM_SHA256) per RFC 9001 Section 5.1.
  /// The AEAD key is 16 bytes and the header-protection key is 16 bytes.
  ///
  /// Per RFC 9001 §4.1.4, endpoints MUST discard Handshake keys once
  /// the TLS handshake is complete and 1-RTT (Application) keys are available.
  static Future<KeyManager> deriveApplication(
    SecretKey clientSecret,
    SecretKey serverSecret,
    CryptoBackend backend,
  ) async {
    final manager = KeyManager._();
    final aead = Aes128Gcm();
    final keyLength = aead.keyLength; // 16 bytes
    const hpKeyLength = 16; // AES-128 header protection key

    // In a full implementation, client/server directionality is tracked
    // separately. Here we use client keys for the pipeline scaffold.
    final clientKeys = await KeyDerivation.deriveKeys(
      secret: clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.application] = PacketNumberSpaceKeys(
      protector: PacketProtector(
        backend: backend,
        aead: aead,
        key: SimpleSecretKey(clientKeys.key),
        iv: clientKeys.iv,
      ),
      headerProtection: HeaderProtection(
        hpKey: clientKeys.hpKey,
        isChaCha20: false,
      ),
    );

    return manager;
  }

  /// Derive 0-RTT keys from a PSK (pre-shared key).
  ///
  /// 0-RTT keys are used before the handshake completes to send early data.
  /// They are derived using the same labels as 1-RTT keys but from the PSK
  /// instead of the handshake traffic secret.
  ///
  /// Uses AES-128-GCM (mandatory QUIC cipher suite) with a 16-byte key and
  /// 16-byte header-protection key per RFC 9001 Section 5.1.
  ///
  /// **IMPORTANT:** 0-RTT keys MUST be discarded once 1-RTT (Application) keys
  /// are available. Call [discardZeroRttKeys] after the handshake completes.
  static Future<KeyManager> deriveZeroRtt(
    SecretKey psk,
    CryptoBackend backend,
  ) async {
    final manager = KeyManager._();
    final aead = Aes128Gcm();
    final keyLength = aead.keyLength; // 16 bytes
    const hpKeyLength = 16; // AES-128 header protection key

    final keys = await ZeroRttHelper.deriveKeys(
      psk: psk,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.zeroRtt] = PacketNumberSpaceKeys(
      protector: PacketProtector(
        backend: backend,
        aead: aead,
        key: SimpleSecretKey(keys.key),
        iv: keys.iv,
      ),
      headerProtection: HeaderProtection(
        hpKey: keys.hpKey,
        isChaCha20: false,
      ),
    );

    return manager;
  }

  /// Discard Initial keys after the handshake is confirmed.
  ///
  /// Per RFC 9001 Section 4.1.4, endpoints MUST discard Initial keys once
  /// they have received an ACK for all CRYPTO data sent in Initial packets
  /// and all Handshake CRYPTO data has been sent.
  void discardInitialKeys() {
    _keys.remove(PacketNumberSpace.initial);
  }

  /// Discard Handshake keys after the handshake is complete.
  ///
  /// Per RFC 9001 Section 4.1.4, endpoints MUST discard Handshake keys once
  /// the TLS handshake is complete and 1-RTT (Application) keys are available.
  void discardHandshakeKeys() {
    _keys.remove(PacketNumberSpace.handshake);
  }

  /// Discard 0-RTT keys after the 1-RTT handshake completes.
  ///
  /// 0-RTT keys are used before the handshake completes and MUST be discarded
  /// once 1-RTT (Application) keys are available. Per RFC 9001, endpoints
  /// must not retain 0-RTT keys beyond the handshake to prevent replay
  /// attacks and key confusion.
  void discardZeroRttKeys() {
    _keys.remove(PacketNumberSpace.zeroRtt);
  }

  /// Remove keys for a space (e.g., after handshake completion, Initial keys
  /// are discarded per RFC 9001 Section 4.1.4).
  void discardKeys(PacketNumberSpace space) {
    _keys.remove(space);
  }
}

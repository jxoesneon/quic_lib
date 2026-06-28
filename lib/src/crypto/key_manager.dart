import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/key_derivation.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/crypto/packet/packet_protector.dart';
import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';

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

  /// Remove keys for a space (e.g., after handshake completion, Initial keys
  /// are discarded per RFC 9001 Section 4.1.4).
  void discardKeys(PacketNumberSpace space) {
    _keys.remove(space);
  }
}

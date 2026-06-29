import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/key_derivation.dart';
import 'package:quic_lib/src/crypto/zero_rtt_helper.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/crypto/packet/packet_protector.dart';
import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';

// Re-export for test convenience.
export 'initial_secrets.dart' show SimpleSecretKey;

/// Client and server keys for a single packet number space.
class _DirectionalKeys {
  final PacketNumberSpaceKeys client;
  final PacketNumberSpaceKeys server;

  _DirectionalKeys({required this.client, required this.server});
}

/// Derives and manages packet protection keys for all QUIC packet number spaces.
///
/// Per RFC 9001, each space has independent keys:
/// - Initial keys: derived from DCID using the fixed initial salt
/// - Handshake keys: derived from the TLS handshake traffic secret
/// - Application keys: derived from the TLS application traffic secret
///
/// Client and server keys are tracked separately per space so that the
/// correct directional keys can be selected for sending and receiving.
class KeyManager {
  /// Role of the endpoint that owns this key manager.
  final HandshakeRole role;

  final Map<PacketNumberSpace, _DirectionalKeys> _keys = {};

  KeyManager._(this.role);

  /// Create a [KeyManager] with pre-derived keys for testing.
  KeyManager.forTest() : role = HandshakeRole.client;

  /// Derive Initial-space keys from the destination connection ID.
  static Future<KeyManager> deriveInitial(
    List<int> destinationConnectionId,
    CryptoBackend backend, {
    HandshakeRole role = HandshakeRole.client,
  }) async {
    final manager = KeyManager._(role);
    final secrets = await InitialSecrets.derive(
      destinationConnectionId,
      backend: backend,
    );

    final aead = Aes128Gcm();
    final keyLength = aead.keyLength;
    const hpKeyLength = 16;

    final clientKeys = await KeyDerivation.deriveKeys(
      secret: secrets.clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    final serverKeys = await KeyDerivation.deriveKeys(
      secret: secrets.serverSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.initial] = _DirectionalKeys(
      client: PacketNumberSpaceKeys(
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
      ),
      server: PacketNumberSpaceKeys(
        protector: PacketProtector(
          backend: backend,
          aead: aead,
          key: SimpleSecretKey(serverKeys.key),
          iv: serverKeys.iv,
        ),
        headerProtection: HeaderProtection(
          hpKey: serverKeys.hpKey,
          isChaCha20: false,
        ),
      ),
    );

    return manager;
  }

  /// Get the local keys for a packet number space (used for sending),
  /// or null if not yet derived.
  PacketNumberSpaceKeys? keysFor(PacketNumberSpace space) {
    final dir = _keys[space];
    if (dir == null) return null;
    return role == HandshakeRole.client ? dir.client : dir.server;
  }

  /// Get the peer's keys for a packet number space (used for receiving),
  /// or null if not yet derived.
  PacketNumberSpaceKeys? peerKeysFor(PacketNumberSpace space) {
    final dir = _keys[space];
    if (dir == null) return null;
    return role == HandshakeRole.client ? dir.server : dir.client;
  }

  /// Install keys for a packet number space (used for Handshake/App transitions).
  void installKeys(
    PacketNumberSpace space,
    PacketNumberSpaceKeys keys, {
    PacketNumberSpaceKeys? peerKeys,
  }) {
    if (peerKeys != null) {
      _keys[space] = _DirectionalKeys(
        client: role == HandshakeRole.client ? keys : peerKeys,
        server: role == HandshakeRole.server ? keys : peerKeys,
      );
    } else {
      // If only one set is provided, use it for both directions.
      _keys[space] = _DirectionalKeys(client: keys, server: keys);
    }
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
    CryptoBackend backend, {
    HandshakeRole role = HandshakeRole.client,
  }) async {
    final manager = KeyManager._(role);
    final aead = Aes256Gcm();
    final keyLength = aead.keyLength;
    const hpKeyLength = 16;

    final clientKeys = await KeyDerivation.deriveKeys(
      secret: clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    final serverKeys = await KeyDerivation.deriveKeys(
      secret: serverSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.handshake] = _DirectionalKeys(
      client: PacketNumberSpaceKeys(
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
      ),
      server: PacketNumberSpaceKeys(
        protector: PacketProtector(
          backend: backend,
          aead: aead,
          key: SimpleSecretKey(serverKeys.key),
          iv: serverKeys.iv,
        ),
        headerProtection: HeaderProtection(
          hpKey: serverKeys.hpKey,
          isChaCha20: false,
        ),
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
    CryptoBackend backend, {
    HandshakeRole role = HandshakeRole.client,
  }) async {
    final manager = KeyManager._(role);
    final aead = Aes128Gcm();
    final keyLength = aead.keyLength;
    const hpKeyLength = 16;

    final clientKeys = await KeyDerivation.deriveKeys(
      secret: clientSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    final serverKeys = await KeyDerivation.deriveKeys(
      secret: serverSecret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.application] = _DirectionalKeys(
      client: PacketNumberSpaceKeys(
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
      ),
      server: PacketNumberSpaceKeys(
        protector: PacketProtector(
          backend: backend,
          aead: aead,
          key: SimpleSecretKey(serverKeys.key),
          iv: serverKeys.iv,
        ),
        headerProtection: HeaderProtection(
          hpKey: serverKeys.hpKey,
          isChaCha20: false,
        ),
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
    CryptoBackend backend, {
    HandshakeRole role = HandshakeRole.client,
  }) async {
    final manager = KeyManager._(role);
    final aead = Aes128Gcm();
    final keyLength = aead.keyLength;
    const hpKeyLength = 16;

    final keys = await ZeroRttHelper.deriveKeys(
      psk: psk,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );

    final spaceKeys = PacketNumberSpaceKeys(
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

    // 0-RTT keys are symmetric: both directions use the same key.
    manager._keys[PacketNumberSpace.zeroRtt] = _DirectionalKeys(
      client: spaceKeys,
      server: spaceKeys,
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

  // ---- Key Update Tracking (RFC 9001 Section 6) ----

  /// Current key phase (0 or 1) for application data.
  int _keyPhase = 0;

  /// Number of packets encrypted with the current application key phase.
  int _packetsWithCurrentKey = 0;

  /// Whether a key update is currently pending (waiting for peer confirmation).
  bool _keyUpdatePending = false;

  /// Lowest packet number sent with the current key phase.
  int _lowestPacketWithCurrentKey = -1;

  /// Highest packet number acknowledged in the 1-RTT space.
  int _highestAckedPacket = -1;

  /// Confidentiality limits per cipher suite (RFC 9001 Section 5.5).
  static const int _aesGcmConfidentialityLimit = 0x800000; // 2^23
  static const int _chachaConfidentialityLimit = 0x1000000000; // 2^36

  /// Current key phase (0 or 1).
  int get keyPhase => _keyPhase;

  /// Whether a key update is pending.
  bool get keyUpdatePending => _keyUpdatePending;

  /// Notify the key manager that a packet was sent with the current application keys.
  /// Returns `true` if the confidentiality limit has been reached and a key
  /// update SHOULD be initiated.
  bool onPacketSentWithCurrentKey(int packetNumber, {bool isChaCha20 = false}) {
    _packetsWithCurrentKey++;
    if (_lowestPacketWithCurrentKey < 0 ||
        packetNumber < _lowestPacketWithCurrentKey) {
      _lowestPacketWithCurrentKey = packetNumber;
    }

    final limit = isChaCha20
        ? _chachaConfidentialityLimit
        : _aesGcmConfidentialityLimit;
    if (_packetsWithCurrentKey >= limit) {
      return true;
    }
    return false;
  }

  /// Notify the key manager that an ACK was received for a packet in the
  /// 1-RTT space.
  void onAckReceived(int packetNumber) {
    if (packetNumber > _highestAckedPacket) {
      _highestAckedPacket = packetNumber;
    }
  }

  /// Initiate a key update by toggling the key phase.
  ///
  /// Per RFC 9001 §6.1, endpoints MUST NOT initiate a subsequent key update
  /// unless it has received an ACK for a packet sent with the current key phase.
  ///
  // TODO(issue): peer-initiated key update detection per RFC 9001 §6.2 is
  // not yet implemented. This only affects long-lived connections where the
  // peer initiates a key update before the local endpoint does. Tracked for
  // v1.5.0.
  void initiateKeyUpdate() {
    if (_keyUpdatePending) {
      throw StateError('Key update already pending');
    }
    if (_lowestPacketWithCurrentKey >= 0 &&
        _highestAckedPacket < _lowestPacketWithCurrentKey) {
      throw StateError(
          'Cannot initiate key update: no ACK received for packets sent with current key phase');
    }
    _keyPhase ^= 1;
    _packetsWithCurrentKey = 0;
    _lowestPacketWithCurrentKey = -1;
    _keyUpdatePending = true;
  }

  /// Confirm the key update once an ACK is received for a packet sent
  /// with the new keys.
  void confirmKeyUpdate() {
    _keyUpdatePending = false;
  }
}

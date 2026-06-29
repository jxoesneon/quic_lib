

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/key_derivation.dart';
import 'package:quic_lib/src/crypto/packet/key_update.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/crypto/packet/packet_protector.dart';
import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/crypto/zero_rtt_helper.dart';
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

  /// Crypto backend used for key derivation. Set during construction.
  final CryptoBackend _backend;

  final Map<PacketNumberSpace, _DirectionalKeys> _keys = {};

  /// Next-generation keys for each packet number space, derived proactively to
  /// avoid timing side-channels when a peer-initiated key update is detected.
  final Map<PacketNumberSpace, _DirectionalKeys> _nextKeys = {};

  /// Previous-generation keys retained for the PTO reordering window after a key
  /// update (RFC 9001 Section 6.5).
  final Map<PacketNumberSpace, _DirectionalKeys> _previousKeys = {};

  KeyManager._(this.role, this._backend);

  /// Create a [KeyManager] with no keys for testing key-phase tracking logic.
  ///
  /// For tests that need real application keys, use [forTestWithKeys].
  KeyManager.forTest()
      : role = HandshakeRole.client,
        _backend = DefaultCryptoBackend();

  /// Create a [KeyManager] with real derived application keys for testing
  /// key updates, header protection, and AEAD round-trips.
  ///
  /// Both client and server roles are derived from the same pair of
  /// deterministic secrets, so their directional keys match and packets can be
  /// round-tripped between two test endpoints.
  static Future<KeyManager> forTestWithKeys(
      {HandshakeRole role = HandshakeRole.client,
      CryptoBackend? backend}) async {
    final effectiveBackend = backend ?? DefaultCryptoBackend();
    final clientSecret = SimpleSecretKey(List<int>.generate(32, (i) => i));
    final serverSecret = SimpleSecretKey(List<int>.generate(32, (i) => i + 32));
    return deriveApplication(
      clientSecret,
      serverSecret,
      effectiveBackend,
      role: role,
    );
  }

  /// Derive Initial-space keys from the destination connection ID.
  static Future<KeyManager> deriveInitial(
    List<int> destinationConnectionId,
    CryptoBackend backend, {
    HandshakeRole role = HandshakeRole.client,
  }) async {
    final manager = KeyManager._(role, backend);
    final secrets = await InitialSecrets.derive(
      destinationConnectionId,
      backend: backend,
    );

    manager._keys[PacketNumberSpace.initial] =
        await _deriveDirectionalKeys(
      secrets.clientSecret,
      secrets.serverSecret,
      backend,
      Aes128Gcm(),
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

  /// Derive a [PacketNumberSpaceKeys] from a traffic [secret] and [aead].
  static Future<PacketNumberSpaceKeys> _deriveSpaceKeys(
    SecretKey secret,
    CryptoBackend backend,
    AeadAlgorithm aead,
  ) async {
    final keyLength = aead.keyLength;
    const hpKeyLength = 16;
    final derived = await KeyDerivation.deriveKeys(
      secret: secret,
      keyLength: keyLength,
      hpKeyLength: hpKeyLength,
      backend: backend,
    );
    return PacketNumberSpaceKeys(
      protector: PacketProtector(
        backend: backend,
        aead: aead,
        key: SimpleSecretKey(derived.key),
        iv: derived.iv,
      ),
      headerProtection: HeaderProtection(
        hpKey: derived.hpKey,
        isChaCha20: false,
      ),
    );
  }

  /// Derive a [_DirectionalKeys] pair for [clientSecret] and [serverSecret].
  static Future<_DirectionalKeys> _deriveDirectionalKeys(
    SecretKey clientSecret,
    SecretKey serverSecret,
    CryptoBackend backend,
    AeadAlgorithm aead,
  ) async {
    final clientKeys = await _deriveSpaceKeys(clientSecret, backend, aead);
    final serverKeys = await _deriveSpaceKeys(serverSecret, backend, aead);
    return _DirectionalKeys(client: clientKeys, server: serverKeys);
  }

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
    final manager = KeyManager._(role, backend);

    manager._keys[PacketNumberSpace.handshake] =
        await _deriveDirectionalKeys(
      clientSecret,
      serverSecret,
      backend,
      Aes256Gcm(),
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
    final manager = KeyManager._(role, backend);
    final aead = Aes128Gcm();

    // Track the application traffic secrets so that next-generation keys can be
    // derived proactively (RFC 9001 Section 6). Proactive derivation avoids
    // timing side-channels when a peer-initiated key update is detected.
    manager._localAppSecret =
        role == HandshakeRole.client ? clientSecret : serverSecret;
    manager._peerAppSecret =
        role == HandshakeRole.client ? serverSecret : clientSecret;

    manager._keys[PacketNumberSpace.application] =
        await _deriveDirectionalKeys(
      clientSecret,
      serverSecret,
      backend,
      aead,
    );

    await manager._deriveNextApplicationKeys();

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
    final manager = KeyManager._(role, backend);
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

  /// Local application traffic secret for the current key phase.
  SecretKey? _localAppSecret;

  /// Peer application traffic secret for the current key phase.
  SecretKey? _peerAppSecret;

  /// Local application traffic secret for the next key phase.
  SecretKey? _nextLocalAppSecret;

  /// Peer application traffic secret for the next key phase.
  SecretKey? _nextPeerAppSecret;

  /// Highest packet number received in the current key phase.
  int _highestPacketReceivedWithCurrentKey = -1;

  /// Lowest packet number received in the current key phase.
  int _lowestPacketReceivedWithCurrentKey = -1;

  /// Highest packet number received in the 1-RTT space across all key phases.
  int _highestPacketReceivedOverall = -1;

  /// Microsecond timestamp at which the previous-generation application keys
  /// should be discarded (3×PTO after a key update, per RFC 9001 Section 6.5).
  /// A value of -1 means no discard deadline is currently set.
  int _previousKeyDiscardDeadlineUs = -1;

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

  /// Derive next-generation application keys from the current secrets and store
  /// them in [_nextKeys]. Called during application-key derivation and after
  /// every key update.
  Future<void> _deriveNextApplicationKeys() async {
    final localSecret = _localAppSecret;
    final peerSecret = _peerAppSecret;
    if (localSecret == null || peerSecret == null) {
      throw StateError('Application secrets not available');
    }

    _nextLocalAppSecret = await KeyUpdate.deriveNextSecret(
      currentSecret: localSecret,
      backend: _backend,
    );
    _nextPeerAppSecret = await KeyUpdate.deriveNextSecret(
      currentSecret: peerSecret,
      backend: _backend,
    );

    final derivedNextKeys = await _deriveDirectionalKeys(
      role == HandshakeRole.client
          ? _nextLocalAppSecret!
          : _nextPeerAppSecret!,
      role == HandshakeRole.client
          ? _nextPeerAppSecret!
          : _nextLocalAppSecret!,
      _backend,
      Aes128Gcm(),
    );

    // RFC 9001 Section 5.4: the same header protection key is used for the
    // duration of the connection; it does not change after a key update.
    // Reuse the current generation's header protection for the next generation.
    final currentKeys = _keys[PacketNumberSpace.application];
    if (currentKeys != null) {
      _nextKeys[PacketNumberSpace.application] = _DirectionalKeys(
        client: PacketNumberSpaceKeys(
          protector: derivedNextKeys.client.protector,
          headerProtection: currentKeys.client.headerProtection,
        ),
        server: PacketNumberSpaceKeys(
          protector: derivedNextKeys.server.protector,
          headerProtection: currentKeys.server.headerProtection,
        ),
      );
    } else {
      _nextKeys[PacketNumberSpace.application] = derivedNextKeys;
    }
  }

  /// Promote next-generation keys to current, retain old keys as previous,
  /// and derive a fresh next generation.
  Future<void> _rotateApplicationKeys() async {
    final application = PacketNumberSpace.application;
    final current = _keys[application];
    final next = _nextKeys[application];
    if (current == null || next == null) {
      throw StateError('Application keys not available for rotation');
    }

    // Retain old keys for the reordering window.
    _previousKeys[application] = current;
    _keys[application] = next;

    // Promote next secrets to current.
    _localAppSecret = _nextLocalAppSecret;
    _peerAppSecret = _nextPeerAppSecret;

    await _deriveNextApplicationKeys();
  }

  /// Get the local send keys for a specific [phase] in the Application space,
  /// or null if they are not available. Phases are 0 or 1.
  PacketNumberSpaceKeys? keysForPhase(int phase) {
    if (phase != 0 && phase != 1) {
      throw ArgumentError('Key phase must be 0 or 1');
    }
    if (phase == _keyPhase) {
      return keysFor(PacketNumberSpace.application);
    }
    final dir = _nextKeys[PacketNumberSpace.application] ??
        _previousKeys[PacketNumberSpace.application];
    if (dir == null) return null;
    return role == HandshakeRole.client ? dir.client : dir.server;
  }

  /// Get the peer receive keys for a specific [phase] in the Application space,
  /// or null if they are not available. Phases are 0 or 1.
  ///
  /// This returns the peer keys for the exact generation matching [phase] if it
  /// is the current generation; for packets from a different phase use
  /// [receiveKeysForPhase] to select between previous and next-generation keys.
  PacketNumberSpaceKeys? peerKeysForPhase(int phase) {
    if (phase != 0 && phase != 1) {
      throw ArgumentError('Key phase must be 0 or 1');
    }
    if (phase == _keyPhase) {
      return peerKeysFor(PacketNumberSpace.application);
    }
    // Phase 0 and 1 toggle; the non-current phase could be either the previous
    // or the next generation. Prefer the next generation if it exists.
    final dir = _nextKeys[PacketNumberSpace.application] ??
        _previousKeys[PacketNumberSpace.application];
    if (dir == null) return null;
    return role == HandshakeRole.client ? dir.server : dir.client;
  }

  /// Select the correct receive keys for an incoming 1-RTT short-header packet
  /// with the given [phase] and [packetNumber].
  ///
  /// Per RFC 9001 Section 6.5, a packet number higher than any packet number in
  /// the current key phase requires the next-generation keys; a packet number
  /// lower than any packet number in the current key phase uses the previous
  /// generation keys. Packet numbers falling within the current phase range are
  /// ambiguous and are rejected by returning null.
  ///
  /// Returns null if the appropriate keys are not available.
  PacketNumberSpaceKeys? receiveKeysForPhase(int phase, int packetNumber) {
    if (phase != 0 && phase != 1) {
      throw ArgumentError('Key phase must be 0 or 1');
    }
    if (phase == _keyPhase) {
      return peerKeysFor(PacketNumberSpace.application);
    }

    final application = PacketNumberSpace.application;
    final lowestCurrent = _lowestPacketReceivedWithCurrentKey;
    final highestCurrent = _highestPacketReceivedWithCurrentKey;

    PacketNumberSpaceKeys? nextKeys() => _nextKeys[application] != null
        ? (role == HandshakeRole.client
            ? _nextKeys[application]!.server
            : _nextKeys[application]!.client)
        : null;

    PacketNumberSpaceKeys? previousKeys() => _previousKeys[application] != null
        ? (role == HandshakeRole.client
            ? _previousKeys[application]!.server
            : _previousKeys[application]!.client)
        : null;

    if (highestCurrent >= 0) {
      if (packetNumber > highestCurrent) {
        return nextKeys();
      }
      if (lowestCurrent >= 0 && packetNumber < lowestCurrent) {
        return previousKeys();
      }
      // Packet number falls within the current phase range: ambiguous.
      return null;
    }

    // No packets have been received in the current phase yet. If the packet
    // number is lower than or equal to the highest overall received packet,
    // treat it as a reordered packet from the previous generation; otherwise,
    // treat it as a new key update.
    if (_highestPacketReceivedOverall >= 0 &&
        packetNumber <= _highestPacketReceivedOverall) {
      return previousKeys();
    }
    return nextKeys();
  }

  /// Handle a peer-initiated key update (RFC 9001 Section 6.2).
  ///
  /// The caller supplies the [packetNumber] and [keyPhase] from the received
  /// 1-RTT short-header packet. If the peer's key phase differs from the local
  /// phase and the packet number is higher than any packet seen in the current
  /// phase, this method promotes the pre-derived next-generation keys to
  /// current, updates the local send keys to match, and resets tracking state.
  ///
  /// Throws [StateError] for invalid key phases or if the key phase transition
  /// is not monotonic (potential rollback attack).
  Future<void> onPeerKeyUpdateDetected(int packetNumber, int keyPhase) async {
    if (keyPhase != 0 && keyPhase != 1) {
      throw StateError('Invalid key phase: $keyPhase');
    }
    if (packetNumber < 0) {
      throw StateError('Invalid packet number: $packetNumber');
    }

    if (keyPhase == _keyPhase) {
      // No phase change; update packet number bounds for the current phase.
      if (_lowestPacketReceivedWithCurrentKey < 0 ||
          packetNumber < _lowestPacketReceivedWithCurrentKey) {
        _lowestPacketReceivedWithCurrentKey = packetNumber;
      }
      if (packetNumber > _highestPacketReceivedWithCurrentKey) {
        _highestPacketReceivedWithCurrentKey = packetNumber;
      }
      if (packetNumber > _highestPacketReceivedOverall) {
        _highestPacketReceivedOverall = packetNumber;
      }
      return;
    }

    // Peer has toggled to the opposite phase. Per RFC 9001 Section 6.5:
    // - packet number < lowest current phase packet -> reordered previous packet
    // - packet number > highest current phase packet -> new key update
    // - packet number within current phase range -> ambiguous, reject
    final lowestCurrent = _lowestPacketReceivedWithCurrentKey;
    final highestCurrent = _highestPacketReceivedWithCurrentKey;

    if (lowestCurrent >= 0 &&
        highestCurrent >= 0 &&
        packetNumber >= lowestCurrent &&
        packetNumber <= highestCurrent) {
      throw StateError(
        'Ambiguous key phase transition: packet $packetNumber with phase '
        '$keyPhase falls within the current phase range '
        '($lowestCurrent..$highestCurrent)',
      );
    }

    final bool isReordered;
    if (highestCurrent >= 0) {
      isReordered = packetNumber < lowestCurrent;
    } else if (_highestPacketReceivedOverall >= 0) {
      isReordered = packetNumber <= _highestPacketReceivedOverall;
    } else {
      isReordered = false;
    }

    if (isReordered) {
      // Reordered packet from the previous key phase; do not rotate keys.
      return;
    }

    // A second key update before the previous one has been acknowledged is a
    // protocol violation (RFC 9001 Section 6.2).
    if (_keyUpdatePending) {
      throw StateError(
        'Key update already pending: peer initiated a second key update '
        'before the previous update was acknowledged',
      );
    }

    await _rotateApplicationKeys();
    _keyPhase ^= 1;
    _keyUpdatePending = true;
    _packetsWithCurrentKey = 0;
    _lowestPacketWithCurrentKey = -1;
    _highestPacketReceivedWithCurrentKey = packetNumber;
    _lowestPacketReceivedWithCurrentKey = packetNumber;
    if (packetNumber > _highestPacketReceivedOverall) {
      _highestPacketReceivedOverall = packetNumber;
    }
  }

  /// Initiate a key update by toggling the key phase.
  ///
  /// Per RFC 9001 §6.1, endpoints MUST NOT initiate a subsequent key update
  /// unless it has received an ACK for a packet sent with the current key phase.
  ///
  /// This method derives the next-generation application keys and promotes them
  /// to current. The old keys are retained as [_previousKeys] for the PTO
  /// reordering window.
  Future<void> initiateKeyUpdate() async {
    if (_keyUpdatePending) {
      throw StateError('Key update already pending');
    }
    if (_lowestPacketWithCurrentKey >= 0 &&
        _highestAckedPacket < _lowestPacketWithCurrentKey) {
      throw StateError(
          'Cannot initiate key update: no ACK received for packets sent with current key phase');
    }
    await _rotateApplicationKeys();
    _keyPhase ^= 1;
    _packetsWithCurrentKey = 0;
    _lowestPacketWithCurrentKey = -1;
    _keyUpdatePending = true;
  }

  /// Confirm the key update once the peer has acknowledged the new key phase.
  ///
  /// After confirmation, the previous-generation keys can be discarded.
  void confirmKeyUpdate() {
    _keyUpdatePending = false;
    _discardPreviousKeys();
  }

  /// Discard the previous-generation application keys and cancel the discard
  /// deadline, without clearing the pending-update flag. Used when the 3×PTO
  /// reordering window expires before the peer has acknowledged the update.
  void _discardPreviousKeys() {
    _previousKeys.remove(PacketNumberSpace.application);
    _previousKeyDiscardDeadlineUs = -1;
  }

  /// Set the deadline at which the previous-generation application keys should
  /// be discarded. The caller should pass the current time and the current PTO
  /// duration; the deadline is set to [currentTimeUs] + 3 × [ptoUs].
  void setPreviousKeyDiscardDeadline(int currentTimeUs, int ptoUs) {
    if (_previousKeys[PacketNumberSpace.application] != null) {
      _previousKeyDiscardDeadlineUs = currentTimeUs + 3 * ptoUs;
    }
  }

  /// Discard the previous-generation application keys if the 3×PTO deadline has
  /// passed. Returns true if keys were discarded.
  bool maybeDiscardPreviousKeys(int currentTimeUs) {
    final deadline = _previousKeyDiscardDeadlineUs;
    if (deadline >= 0 && currentTimeUs >= deadline) {
      _discardPreviousKeys();
      return true;
    }
    return false;
  }
}

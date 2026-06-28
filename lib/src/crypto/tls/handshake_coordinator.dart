import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/crypto/tls/transcript_hash.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/frame.dart';

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

/// Orchestrates the full TLS 1.3 handshake key exchange.
///
/// 1. Generates an ephemeral X25519 key pair.
/// 2. On receiving a ClientHello, extracts the peer's public key from the
///    key_share extension, computes the shared secret, and derives the
///    handshake traffic secrets.
/// 3. Derives the master secret and application traffic secrets.
/// 4. Computes and verifies Finished messages.
/// 5. Installs Handshake- and Application-space keys into a [KeyManager].
class HandshakeCoordinator {
  final CryptoBackend backend;
  final HandshakeRole role;
  final KeyManager keyManager;
  final HandshakeKeyExchange _keyExchange;
  final TranscriptHash _transcriptHash;

  ({SecretKey clientSecret, SecretKey serverSecret})? _trafficSecrets;
  SecretKey? _masterSecret;

  /// Creates a new [HandshakeCoordinator].
  HandshakeCoordinator({
    required this.backend,
    required this.role,
    required this.keyManager,
  })  : _keyExchange = HandshakeKeyExchange(backend, role),
        _transcriptHash = TranscriptHash(backend);

  /// Generates ephemeral X25519 keys for this endpoint.
  Future<void> generateKeys() => _keyExchange.generateEphemeralKeys();

  /// True if ephemeral keys have been generated.
  bool get hasGeneratedKeys => _keyExchange.publicKey != null;

  /// The running transcript hash of all handshake messages processed so far.
  TranscriptHash get transcriptHash => _transcriptHash;

  /// Processes an incoming ClientHello [frame], extracts the peer's X25519
  /// public key from the key_share extension, computes the shared secret,
  /// and derives the handshake traffic secrets.
  ///
  /// Returns the derived handshake [SecretKey].
  ///
  /// Throws [StateError] if the ClientHello cannot be parsed.
  Future<SecretKey> processClientHello(CryptoFrame clientHello) async {
    final peerPublicKey = _extractX25519PublicKey(clientHello.data);

    await _transcriptHash.addMessage(clientHello.data);

    final sharedSecret = await _keyExchange.computeSharedSecret(peerPublicKey);

    final helloHash = _transcriptHash.currentHash;

    final handshakeSecret = await _keyExchange.deriveHandshakeSecret(
      sharedSecret,
      helloHash,
    );
    _trafficSecrets = await _keyExchange.deriveTrafficSecrets(
      handshakeSecret,
      transcriptHash: helloHash,
    );

    return handshakeSecret;
  }

  /// Derives and installs Handshake-space keys into [keyManager].
  Future<void> installHandshakeKeys() async {
    if (_trafficSecrets == null) {
      throw StateError(
        'Traffic secrets not available. Call processClientHello first.',
      );
    }

    final derivedManager = await KeyManager.deriveHandshake(
      _trafficSecrets!.clientSecret,
      _trafficSecrets!.serverSecret,
      backend,
      role: role,
    );

    final keys = derivedManager.keysFor(PacketNumberSpace.handshake)!;
    keyManager.installKeys(PacketNumberSpace.handshake, keys);
  }

  /// Derives the master secret from the handshake secret and stores it.
  ///
  /// Call this after the ServerHello has been processed and the transcript
  /// hash includes ClientHello + ServerHello.
  Future<void> deriveMasterSecret(SecretKey handshakeSecret) async {
    _masterSecret = await _keyExchange.deriveMasterSecret(handshakeSecret);
  }

  /// Derives and installs Application-space (1-RTT) keys into [keyManager].
  ///
  /// [transcriptHash] must be the hash of all handshake messages up to and
  /// including the server's Finished message.
  Future<void> installApplicationKeys({List<int>? transcriptHash}) async {
    if (_masterSecret == null) {
      throw StateError(
        'Master secret not available. Call deriveMasterSecret first.',
      );
    }

    final appSecrets = await _keyExchange.deriveApplicationSecrets(
      _masterSecret!,
      transcriptHash: transcriptHash ?? _transcriptHash.currentHash,
    );

    final derivedManager = await KeyManager.deriveApplication(
      appSecrets.clientSecret,
      appSecrets.serverSecret,
      backend,
      role: role,
    );

    final keys = derivedManager.keysFor(PacketNumberSpace.application)!;
    keyManager.installKeys(PacketNumberSpace.application, keys);
  }

  /// Computes the Finished verify data for this endpoint.
  ///
  /// [baseSecret] is the client or server handshake traffic secret.
  /// [transcriptHash] is the hash of all handshake messages before the
  /// Finished message itself.
  Future<List<int>> computeFinishedVerifyData(
    SecretKey baseSecret,
    List<int> transcriptHash,
  ) async {
    final finishedKey = await _keyExchange.deriveFinishedKey(baseSecret);
    return _keyExchange.computeFinishedVerifyData(finishedKey, transcriptHash);
  }

  /// Verifies a peer's Finished message.
  ///
  /// [peerSecret] is the peer's handshake traffic secret (client hs traffic
  /// if verifying the client's Finished, server hs traffic for the server's).
  /// [finishedData] is the verify_data from the peer's Finished message.
  /// [transcriptHash] is the hash of all handshake messages before the
  /// Finished message itself.
  Future<bool> verifyFinished(
    SecretKey peerSecret,
    List<int> finishedData,
    List<int> transcriptHash,
  ) async {
    final expected =
        await computeFinishedVerifyData(peerSecret, transcriptHash);
    if (expected.length != finishedData.length) return false;
    // SECURITY: Constant-time comparison to prevent timing side-channels.
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ finishedData[i];
    }
    return diff == 0;
  }

  /// Derives the next generation application traffic secret for a key update.
  ///
  /// Per RFC 8446 Section 4.6.3, updates the current application traffic
  /// secret and derives new packet protection keys from it.
  Future<void> performKeyUpdate(SecretKey currentAppSecret) async {
    final nextSecret =
        await _keyExchange.deriveNextGenerationSecret(currentAppSecret);
    // Derive new client/server app secrets from the next-gen secret.
    final hash = Sha256();
    const secretLength = 32;

    final clientBytes = await backend.hkdfExpandLabel(
      hash,
      nextSecret,
      'c ap traffic',
      <int>[],
      secretLength,
    );
    final serverBytes = await backend.hkdfExpandLabel(
      hash,
      nextSecret,
      's ap traffic',
      <int>[],
      secretLength,
    );

    final derivedManager = await KeyManager.deriveApplication(
      SimpleSecretKey(clientBytes),
      SimpleSecretKey(serverBytes),
      backend,
      role: role,
    );

    final keys = derivedManager.keysFor(PacketNumberSpace.application)!;
    keyManager.installKeys(PacketNumberSpace.application, keys);
  }

  /// Attempts to extract an X25519 public key from the key_share extension
  /// inside a ClientHello payload. Throws [StateError] on any parsing failure.
  PublicKey _extractX25519PublicKey(List<int> data) {
    try {
      final message = Uint8List.fromList(data);
      final parsed = parseMessage(message);

      if (parsed.type != TlsHandshakeType.clientHello) {
        throw StateError('Failed to parse ClientHello');
      }

      final payload = parsed.payload;
      var offset = 0;

      // legacy_version (2) + random (32)
      if (payload.length < 34) throw StateError('Failed to parse ClientHello');
      offset += 34;

      // legacy_session_id
      if (offset >= payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      final sessionIdLen = payload[offset++];
      if (offset + sessionIdLen > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      offset += sessionIdLen;

      // cipher_suites
      if (offset + 2 > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      final csLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;
      if (offset + csLen > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      offset += csLen;

      // legacy_compression_methods
      if (offset >= payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      final cmLen = payload[offset++];
      if (offset + cmLen > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      offset += cmLen;

      // extensions
      if (offset + 2 > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      final extLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;
      if (offset + extLen > payload.length) {
        throw StateError('Failed to parse ClientHello');
      }
      final extEnd = offset + extLen;

      while (offset + 4 <= extEnd) {
        final extType = (payload[offset] << 8) | payload[offset + 1];
        final extDataLen = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (extType == 0x0033) {
          // key_share
          if (offset + 2 > extEnd) {
            throw StateError('Failed to parse ClientHello');
          }
          final ksListLen = (payload[offset] << 8) | payload[offset + 1];
          var ksOffset = offset + 2;
          final ksEnd = ksOffset + ksListLen;
          if (ksEnd > extEnd) throw StateError('Failed to parse ClientHello');

          while (ksOffset + 4 <= ksEnd) {
            final group = (payload[ksOffset] << 8) | payload[ksOffset + 1];
            final keyLen = (payload[ksOffset + 2] << 8) | payload[ksOffset + 3];
            ksOffset += 4;
            if (ksOffset + keyLen > ksEnd) {
              throw StateError('Failed to parse ClientHello');
            }

            if (group == 0x001d) {
              // x25519
              final keyBytes = payload.sublist(ksOffset, ksOffset + keyLen);
              return _SimplePublicKey(keyBytes);
            }

            ksOffset += keyLen;
          }
        }

        offset += extDataLen;
      }
    } catch (_) {
      throw StateError('Failed to parse ClientHello');
    }

    throw StateError('Failed to parse ClientHello');
  }
}

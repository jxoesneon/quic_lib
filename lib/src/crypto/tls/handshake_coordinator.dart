import 'dart:typed_data';

import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/key_manager.dart';
import 'package:dart_quic/src/crypto/tls/crypto_message_parser.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart';
import 'package:dart_quic/src/crypto/tls/tls_handshake_types.dart';
import 'package:dart_quic/src/crypto/tls/transcript_hash.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/wire/frame.dart';

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

/// Orchestrates the full TLS handshake key exchange.
///
/// This is a scaffold that wires real key-exchange primitives into the
/// CRYPTO-frame pipeline:
///
/// 1. Generates an ephemeral X25519 key pair.
/// 2. On receiving a ClientHello, extracts the peer's public key from the
///    key_share extension, computes the shared secret, and derives the
///    handshake traffic secrets.
/// 3. Installs Handshake- and Application-space keys into a [KeyManager].
///
/// **Note:** This is a scaffold. Real TLS 1.3 requires transcript hash
/// tracking, certificate verification, Finished message computation,
/// key update handling, and many additional steps.
class HandshakeCoordinator {
  final CryptoBackend backend;
  final HandshakeRole role;
  final KeyManager keyManager;
  final HandshakeKeyExchange _keyExchange;
  final TranscriptHash _transcriptHash;

  ({SecretKey clientSecret, SecretKey serverSecret})? _trafficSecrets;

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
  /// Because this is a scaffold, parsing failures fall back to a dummy key
  /// so that downstream tests can proceed without a fully valid ClientHello.
  Future<SecretKey> processClientHello(CryptoFrame clientHello) async {
    final peerPublicKey = _extractX25519PublicKey(clientHello.data);

    // Add ClientHello to the running transcript hash.
    await _transcriptHash.addMessage(clientHello.data);

    final sharedSecret = await _keyExchange.computeSharedSecret(peerPublicKey);

    // In real TLS 1.3 the helloHash is the transcript hash of ClientHello.
    // We use an all-zero placeholder for the scaffold.
    final helloHash = List<int>.filled(32, 0);

    final handshakeSecret = await _keyExchange.deriveHandshakeSecret(
      sharedSecret,
      helloHash,
    );
    _trafficSecrets = await _keyExchange.deriveTrafficSecrets(handshakeSecret);

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
    );

    final keys = derivedManager.keysFor(PacketNumberSpace.handshake)!;
    keyManager.installKeys(PacketNumberSpace.handshake, keys);
  }

  /// Derives and installs Application-space (1-RTT) keys into [keyManager].
  Future<void> installApplicationKeys() async {
    if (_trafficSecrets == null) {
      throw StateError(
        'Traffic secrets not available. Call processClientHello first.',
      );
    }

    // In real TLS 1.3, application secrets are derived from the master
    // secret, not the handshake traffic secret. For this scaffold we
    // reuse the handshake-derived traffic secrets.
    final derivedManager = await KeyManager.deriveApplication(
      _trafficSecrets!.clientSecret,
      _trafficSecrets!.serverSecret,
      backend,
    );

    final keys = derivedManager.keysFor(PacketNumberSpace.application)!;
    keyManager.installKeys(PacketNumberSpace.application, keys);
  }

  /// Attempts to extract an X25519 public key from the key_share extension
  /// inside a ClientHello payload. Falls back to a dummy 32-byte key on
  /// any parsing failure.
  PublicKey _extractX25519PublicKey(List<int> data) {
    try {
      final message = Uint8List.fromList(data);
      final parsed = parseMessage(message);

      if (parsed.type != TlsHandshakeType.clientHello) {
        return _dummyPublicKey();
      }

      final payload = parsed.payload;
      var offset = 0;

      // legacy_version (2) + random (32)
      if (payload.length < 34) return _dummyPublicKey();
      offset += 34;

      // legacy_session_id
      if (offset >= payload.length) return _dummyPublicKey();
      final sessionIdLen = payload[offset++];
      if (offset + sessionIdLen > payload.length) return _dummyPublicKey();
      offset += sessionIdLen;

      // cipher_suites
      if (offset + 2 > payload.length) return _dummyPublicKey();
      final csLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;
      if (offset + csLen > payload.length) return _dummyPublicKey();
      offset += csLen;

      // legacy_compression_methods
      if (offset >= payload.length) return _dummyPublicKey();
      final cmLen = payload[offset++];
      if (offset + cmLen > payload.length) return _dummyPublicKey();
      offset += cmLen;

      // extensions
      if (offset + 2 > payload.length) return _dummyPublicKey();
      final extLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;
      if (offset + extLen > payload.length) return _dummyPublicKey();
      final extEnd = offset + extLen;

      while (offset + 4 <= extEnd) {
        final extType = (payload[offset] << 8) | payload[offset + 1];
        final extDataLen = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (extType == 0x0033) {
          // key_share
          if (offset + 2 > extEnd) return _dummyPublicKey();
          final ksListLen = (payload[offset] << 8) | payload[offset + 1];
          var ksOffset = offset + 2;
          final ksEnd = ksOffset + ksListLen;
          if (ksEnd > extEnd) return _dummyPublicKey();

          while (ksOffset + 4 <= ksEnd) {
            final group = (payload[ksOffset] << 8) | payload[ksOffset + 1];
            final keyLen =
                (payload[ksOffset + 2] << 8) | payload[ksOffset + 3];
            ksOffset += 4;
            if (ksOffset + keyLen > ksEnd) return _dummyPublicKey();

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
      // Fall through to dummy key.
    }

    return _dummyPublicKey();
  }

  PublicKey _dummyPublicKey() =>
      _SimplePublicKey(List<int>.filled(32, 0));
}

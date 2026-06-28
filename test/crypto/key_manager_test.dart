import 'dart:typed_data';

import 'package:dart_quic/src/crypto/cipher_suites.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/crypto/key_manager.dart';
import 'package:dart_quic/src/crypto/packet/key_derivation.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:test/test.dart';

void main() {
  group('KeyManager', () {
    late DefaultCryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('deriveInitial produces keys for Initial space only', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(dcid, backend);

      expect(manager.hasKeysFor(PacketNumberSpace.initial), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.application), isFalse);
    });

    test('deriveHandshake produces keys for Handshake space', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveHandshake(
        secret,
        secret,
        backend,
      );

      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.initial), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.application), isFalse);
    });

    test('deriveApplication produces keys for Application space', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveApplication(
        secret,
        secret,
        backend,
      );

      expect(manager.hasKeysFor(PacketNumberSpace.application), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.initial), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isFalse);
    });

    test('discardInitialKeys removes Initial but keeps Handshake and App',
        () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(dcid, backend);

      final secret = SimpleSecretKey(Uint8List(32));
      final handshakeMgr = await KeyManager.deriveHandshake(
        secret,
        secret,
        backend,
      );
      final appMgr = await KeyManager.deriveApplication(
        secret,
        secret,
        backend,
      );

      manager.installKeys(
        PacketNumberSpace.handshake,
        handshakeMgr.keysFor(PacketNumberSpace.handshake)!,
      );
      manager.installKeys(
        PacketNumberSpace.application,
        appMgr.keysFor(PacketNumberSpace.application)!,
      );

      expect(manager.hasKeysFor(PacketNumberSpace.initial), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.application), isTrue);

      manager.discardInitialKeys();

      expect(manager.hasKeysFor(PacketNumberSpace.initial), isFalse);
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
      expect(manager.hasKeysFor(PacketNumberSpace.application), isTrue);
    });

    test('key lengths match the cipher suite requirements', () async {
      final secret = SimpleSecretKey(Uint8List(32));

      // Initial / Application: AES-128-GCM => 16-byte key, 16-byte HP key
      final aes128Keys = await KeyDerivation.deriveKeys(
        secret: secret,
        keyLength: Aes128Gcm().keyLength,
        hpKeyLength: 16,
        backend: backend,
      );
      expect(aes128Keys.key.length, equals(16));
      expect(aes128Keys.iv.length, equals(12));
      expect(aes128Keys.hpKey.length, equals(16));

      // Handshake: AES-256-GCM => 32-byte key, 16-byte HP key
      final aes256Keys = await KeyDerivation.deriveKeys(
        secret: secret,
        keyLength: Aes256Gcm().keyLength,
        hpKeyLength: 16,
        backend: backend,
      );
      expect(aes256Keys.key.length, equals(32));
      expect(aes256Keys.iv.length, equals(12));
      expect(aes256Keys.hpKey.length, equals(16));
    });

    test('keysFor returns null for missing space', () async {
      final manager = KeyManager.forTest();
      expect(manager.keysFor(PacketNumberSpace.initial), isNull);
    });

    test('peerKeysFor returns null for missing space', () async {
      final manager = KeyManager.forTest();
      expect(manager.peerKeysFor(PacketNumberSpace.initial), isNull);
    });

    test('keysFor selects correct keys for client role', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(dcid, backend, role: HandshakeRole.client);
      final keys = manager.keysFor(PacketNumberSpace.initial);
      final peerKeys = manager.peerKeysFor(PacketNumberSpace.initial);
      expect(keys, isNotNull);
      expect(peerKeys, isNotNull);
      expect(identical(keys, peerKeys), isFalse);
    });

    test('keysFor selects correct keys for server role', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(dcid, backend, role: HandshakeRole.server);
      final keys = manager.keysFor(PacketNumberSpace.initial);
      final peerKeys = manager.peerKeysFor(PacketNumberSpace.initial);
      expect(keys, isNotNull);
      expect(peerKeys, isNotNull);
      expect(identical(keys, peerKeys), isFalse);
    });

    test('installKeys with peerKeys', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(dcid, backend, role: HandshakeRole.client);
      final clientKeys = manager.keysFor(PacketNumberSpace.initial)!;
      final serverKeys = manager.peerKeysFor(PacketNumberSpace.initial)!;

      final testManager = KeyManager.forTest();
      testManager.installKeys(
        PacketNumberSpace.initial,
        clientKeys,
        peerKeys: serverKeys,
      );

      expect(testManager.keysFor(PacketNumberSpace.initial), isNotNull);
      expect(testManager.peerKeysFor(PacketNumberSpace.initial), isNotNull);
    });

    test('deriveZeroRtt produces keys', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveZeroRtt(secret, backend);
      expect(manager.hasKeysFor(PacketNumberSpace.zeroRtt), isTrue);
    });

    test('deriveInitial with server role', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final manager = await KeyManager.deriveInitial(
        dcid,
        backend,
        role: HandshakeRole.server,
      );
      expect(manager.hasKeysFor(PacketNumberSpace.initial), isTrue);
    });

    test('deriveHandshake with server role', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveHandshake(
        secret,
        secret,
        backend,
        role: HandshakeRole.server,
      );
      expect(manager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
    });

    test('deriveApplication with server role', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final manager = await KeyManager.deriveApplication(
        secret,
        secret,
        backend,
        role: HandshakeRole.server,
      );
      expect(manager.hasKeysFor(PacketNumberSpace.application), isTrue);
    });
  });
}

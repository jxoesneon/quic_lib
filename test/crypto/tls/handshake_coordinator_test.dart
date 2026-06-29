import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_handler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart' as hke;
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart' as hsm;
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';

/// Builds a raw key_share extension for x25519.
Uint8List _buildKeyShareExtension(List<int> keyBytes) {
  final entryLength = 4 + keyBytes.length;
  final listLength = entryLength;
  final extDataLength = 2 + listLength;
  final buffer = BytesBuilder();
  buffer.addByte(0x00);
  buffer.addByte(0x33);
  buffer.addByte((extDataLength >> 8) & 0xFF);
  buffer.addByte(extDataLength & 0xFF);
  buffer.addByte((listLength >> 8) & 0xFF);
  buffer.addByte(listLength & 0xFF);
  buffer.addByte(0x00);
  buffer.addByte(0x1d);
  buffer.addByte((keyBytes.length >> 8) & 0xFF);
  buffer.addByte(keyBytes.length & 0xFF);
  buffer.add(keyBytes);
  return Uint8List.fromList(buffer.toBytes());
}

/// A [MockCryptoBackend] that returns HKDF-Expand-Label outputs of the
/// requested length so that [KeyDerivation.deriveKeys] builds valid
/// [PacketProtector] / [HeaderProtection] instances in tests.
class _TestCryptoBackend extends MockCryptoBackend {
  @override
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  ) =>
      Future.value(List<int>.filled(length, 0));
}

/// Spy that records whether [processClientHello] was invoked.
class _SpyCoordinator extends HandshakeCoordinator {
  bool processClientHelloCalled = false;

  _SpyCoordinator({
    required super.backend,
    required super.role,
    required super.keyManager,
  });

  @override
  Future<SecretKey> processClientHello(CryptoFrame clientHello) async {
    processClientHelloCalled = true;
    return SimpleSecretKey([]);
  }
}

void main() {
  group('HandshakeCoordinator', () {
    late _TestCryptoBackend backend;
    late KeyManager keyManager;
    late HandshakeCoordinator coordinator;

    setUp(() {
      backend = _TestCryptoBackend();
      keyManager = KeyManager.forTest();
      coordinator = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: keyManager,
      );
    });

    test('generates keys successfully', () async {
      expect(coordinator.hasGeneratedKeys, isFalse);
      await coordinator.generateKeys();
      expect(coordinator.hasGeneratedKeys, isTrue);
    });

    test('processClientHello returns a SecretKey', () async {
      await coordinator.generateKeys();

      final random = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(List<int>.filled(32, 0xCD));
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      final secret = await coordinator.processClientHello(frame);
      expect(secret, isA<SecretKey>());
    });

    test('installHandshakeKeys transitions KeyManager to have handshake keys',
        () async {
      await coordinator.generateKeys();

      final random = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(List<int>.filled(32, 0xCD));
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isFalse);

      await coordinator.processClientHello(frame);
      await coordinator.installHandshakeKeys();

      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
    });

    test('installApplicationKeys discards 0-RTT keys per RFC 9001 §4.1.4',
        () async {
      await coordinator.generateKeys();

      // Install 0-RTT keys before the handshake completes.
      final zeroRttManager = await KeyManager.deriveZeroRtt(
        SimpleSecretKey([0xAB, 0xCD]),
        backend,
      );
      final zeroRttKeys = zeroRttManager.keysFor(PacketNumberSpace.zeroRtt)!;
      keyManager.installKeys(PacketNumberSpace.zeroRtt, zeroRttKeys);
      expect(keyManager.hasKeysFor(PacketNumberSpace.zeroRtt), isTrue);

      final random = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(List<int>.filled(32, 0xCD));
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      final handshakeSecret = await coordinator.processClientHello(frame);
      await coordinator.deriveMasterSecret(handshakeSecret);
      await coordinator.installApplicationKeys();

      expect(keyManager.hasKeysFor(PacketNumberSpace.application), isTrue);
      expect(keyManager.hasKeysFor(PacketNumberSpace.zeroRtt), isFalse);
    });
  });

  group('CryptoFrameHandler with coordinator', () {
    test('uses coordinator when a ClientHello is received', () async {
      final assembler = CryptoFrameAssembler();
      final stateMachine = hsm.HandshakeStateMachine(hsm.HandshakeRole.server);
      stateMachine.start();
      stateMachine.accept();

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: stateMachine,
      );

      final backend = _TestCryptoBackend();
      final keyManager = KeyManager.forTest();
      final spy = _SpyCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: keyManager,
      );
      handler.coordinator = spy;

      final random = Uint8List(32);
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      handler.onCryptoFrame(frame);

      // Allow the async processClientHello to run.
      await Future<void>.delayed(Duration.zero);

      expect(spy.processClientHelloCalled, isTrue);
      expect(
        stateMachine.state,
        hsm.HandshakeState.serverWaitFinished,
      );
    });
  });
}

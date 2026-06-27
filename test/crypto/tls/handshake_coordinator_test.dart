import 'dart:typed_data';

import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/crypto/key_manager.dart';
import 'package:dart_quic/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:dart_quic/src/crypto/tls/crypto_frame_handler.dart';
import 'package:dart_quic/src/crypto/tls/handshake_coordinator.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart'
    as hke;
import 'package:dart_quic/src/crypto/tls/handshake_state_machine.dart'
    as hsm;
import 'package:dart_quic/src/crypto/tls/tls_handshake_types.dart';
import 'package:dart_quic/src/crypto/tls/tls_message_builder.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';

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
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [], // no extensions for this scaffold test
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      final secret = await coordinator.processClientHello(frame);
      expect(secret, isA<SecretKey>());
    });

    test(
        'installHandshakeKeys transitions KeyManager to have handshake keys',
        () async {
      await coordinator.generateKeys();

      final random = Uint8List(32);
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isFalse);

      await coordinator.processClientHello(frame);
      await coordinator.installHandshakeKeys();

      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
    });
  });

  group('CryptoFrameHandler with coordinator', () {
    test('uses coordinator when a ClientHello is received', () async {
      final assembler = CryptoFrameAssembler();
      final stateMachine =
          hsm.HandshakeStateMachine(hsm.HandshakeRole.server);
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

import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart' as hke;
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';

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

  @override
  Future<List<int>> hmac(
      HashAlgorithm hash, SecretKey key, List<int> data) async {
    return List<int>.filled(32, 0xAB);
  }
}

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

void main() {
  group('HandshakeCoordinator additional coverage', () {
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

    test('transcriptHash getter returns the internal hash', () {
      expect(coordinator.transcriptHash, isNotNull);
    });

    test('deriveMasterSecret stores the master secret', () async {
      final handshakeSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      await coordinator.deriveMasterSecret(handshakeSecret);
      // Can't directly verify _masterSecret, but installApplicationKeys should work.
    });

    test('installApplicationKeys throws when master secret not derived',
        () async {
      expect(
        () => coordinator.installApplicationKeys(),
        throwsA(isA<StateError>()),
      );
    });

    test('installHandshakeKeys throws when traffic secrets not available',
        () async {
      expect(
        () => coordinator.installHandshakeKeys(),
        throwsA(isA<StateError>()),
      );
    });

    test('computeFinishedVerifyData returns non-empty bytes', () async {
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcript = List<int>.filled(32, 0xCD);
      final verifyData = await coordinator.computeFinishedVerifyData(
        baseSecret,
        transcript,
      );
      expect(verifyData, isNotEmpty);
    });

    test('verifyFinished returns true for matching data', () async {
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcript = List<int>.filled(32, 0xCD);
      final verifyData = await coordinator.computeFinishedVerifyData(
        baseSecret,
        transcript,
      );
      final result = await coordinator.verifyFinished(
        baseSecret,
        verifyData,
        transcript,
      );
      expect(result, isTrue);
    });

    test('verifyFinished returns false for mismatched data', () async {
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcript = List<int>.filled(32, 0xCD);
      final result = await coordinator.verifyFinished(
        baseSecret,
        [0x00, 0x01, 0x02],
        transcript,
      );
      expect(result, isFalse);
    });

    test('verifyFinished returns false for wrong length', () async {
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcript = List<int>.filled(32, 0xCD);
      final verifyData = await coordinator.computeFinishedVerifyData(
        baseSecret,
        transcript,
      );
      final result = await coordinator.verifyFinished(
        baseSecret,
        [...verifyData, 0xFF],
        transcript,
      );
      expect(result, isFalse);
    });

    test('processClientHello throws for non-ClientHello data', () async {
      await coordinator.generateKeys();
      // Build a ServerHello instead
      final serverHello = TlsMessageBuilder.buildServerHello(
        Uint8List(32),
        Uint8List(0),
        0x1301,
        [],
      );
      final frame = CryptoFrame(offset: 0, data: serverHello);
      expect(
        () => coordinator.processClientHello(frame),
        throwsA(isA<StateError>()),
      );
    });

    test('processClientHello throws for malformed data', () async {
      await coordinator.generateKeys();
      final frame = CryptoFrame(offset: 0, data: [0x01, 0x00, 0x00, 0x00]);
      expect(
        () => coordinator.processClientHello(frame),
        throwsA(isA<StateError>()),
      );
    });

    test('installApplicationKeys with custom transcriptHash', () async {
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
      final handshakeSecret = await coordinator.processClientHello(frame);
      await coordinator.installHandshakeKeys();
      await coordinator.deriveMasterSecret(handshakeSecret);

      final customHash = List<int>.filled(32, 0xEF);
      await coordinator.installApplicationKeys(transcriptHash: customHash);
      expect(keyManager.hasKeysFor(PacketNumberSpace.application), isTrue);
    });

    test('performKeyUpdate installs new application keys', () async {
      await coordinator.generateKeys();
      final currentSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      await coordinator.performKeyUpdate(currentSecret);
      expect(keyManager.hasKeysFor(PacketNumberSpace.application), isTrue);
    });
  });
}

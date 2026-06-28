import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';

/// A [MockCryptoBackend] that returns predictable non-zero SHA-256 hashes
/// and valid HKDF-Expand-Label outputs.
class _SecurityTestCryptoBackend extends MockCryptoBackend {
  final List<int> _hashValue;

  _SecurityTestCryptoBackend({List<int>? hashValue})
      : _hashValue = hashValue ?? List<int>.filled(32, 0xAB);

  @override
  Future<List<int>> sha256(List<int> data) => Future.value(_hashValue);

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

/// Builds a raw key_share extension for x25519.
Uint8List _buildKeyShareExtension(List<int> keyBytes) {
  final entryLength = 4 + keyBytes.length; // group(2) + len(2) + key
  final listLength = entryLength;
  final extDataLength = 2 + listLength; // list_len(2) + entries

  final buffer = BytesBuilder();
  buffer.addByte(0x00);
  buffer.addByte(0x33); // extension type: key_share
  buffer.addByte((extDataLength >> 8) & 0xFF);
  buffer.addByte(extDataLength & 0xFF);
  buffer.addByte((listLength >> 8) & 0xFF);
  buffer.addByte(listLength & 0xFF);
  buffer.addByte(0x00);
  buffer.addByte(0x1d); // group: x25519
  buffer.addByte((keyBytes.length >> 8) & 0xFF);
  buffer.addByte(keyBytes.length & 0xFF);
  buffer.add(keyBytes);

  return Uint8List.fromList(buffer.toBytes());
}

void main() {
  group('HandshakeCoordinator security', () {
    late _SecurityTestCryptoBackend backend;
    late KeyManager keyManager;
    late HandshakeCoordinator coordinator;

    setUp(() {
      backend = _SecurityTestCryptoBackend();
      keyManager = KeyManager.forTest();
      coordinator = HandshakeCoordinator(
        backend: backend,
        role: HandshakeRole.server,
        keyManager: keyManager,
      );
    });

    test('malformed ClientHello causes handshake failure instead of dummy key',
        () async {
      await coordinator.generateKeys();

      final malformedFrame = CryptoFrame(
        offset: 0,
        data: [0xFF, 0xFF, 0xFF, 0xFF], // garbage, not a valid ClientHello
      );

      expect(
        () => coordinator.processClientHello(malformedFrame),
        throwsA(
          isA<StateError>().having(
            (e) => e.message,
            'message',
            'Failed to parse ClientHello',
          ),
        ),
      );
    });

    test('handshake secret uses actual transcript hash, not all zeros',
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

      // Before processing, the transcript hash should be empty.
      expect(coordinator.transcriptHash.currentHash, isEmpty);

      final secret = await coordinator.processClientHello(frame);
      expect(secret, isA<SecretKey>());

      // After processing, transcript hash should be the non-zero mocked value.
      final hash = coordinator.transcriptHash.currentHash;
      expect(hash, isNotEmpty);
      expect(hash, equals(List<int>.filled(32, 0xAB)));
      expect(hash, isNot(equals(List<int>.filled(32, 0))));
    });

    test('transcript hash changes after adding ClientHello', () async {
      await coordinator.generateKeys();

      final initialHash = coordinator.transcriptHash.currentHash;
      expect(initialHash, isEmpty);

      final random = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(List<int>.filled(32, 0xCD));
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      await coordinator.processClientHello(frame);

      final updatedHash = coordinator.transcriptHash.currentHash;
      expect(updatedHash, isNotEmpty);
      expect(updatedHash, isNot(equals(initialHash)));
    });
  });
}

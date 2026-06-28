import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/key_manager.dart';
import 'package:dart_quic/src/crypto/tls/handshake_coordinator.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart' as hke;
import 'package:dart_quic/src/crypto/tls/tls_message_builder.dart';
import 'package:dart_quic/src/crypto/tls/transcript_hash.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';

// ---------------------------------------------------------------------------
// A mock backend that actually computes SHA-256 while keeping other crypto
// operations stubbed so that HandshakeCoordinator tests work without
// requiring real X25519/HKDF data.
// ---------------------------------------------------------------------------
class _HashingMockBackend extends MockCryptoBackend {
  final _sha256 = crypto.Sha256();

  @override
  Future<List<int>> sha256(List<int> data) async {
    final hash = await _sha256.hash(data);
    return hash.bytes;
  }

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

void main() {
  group('TranscriptHash', () {
    late _HashingMockBackend backend;
    late TranscriptHash transcriptHash;

    setUp(() {
      backend = _HashingMockBackend();
      transcriptHash = TranscriptHash(backend);
    });

    test('adding a message changes the current hash', () async {
      final initialHash = transcriptHash.currentHash;
      await transcriptHash.addMessage([1, 2, 3]);
      expect(transcriptHash.currentHash, isNot(equals(initialHash)));
      expect(transcriptHash.currentHash, isNotEmpty);
    });

    test('same messages produce same hash', () async {
      final th1 = TranscriptHash(backend);
      final th2 = TranscriptHash(backend);
      await th1.addMessage([1, 2, 3]);
      await th2.addMessage([1, 2, 3]);
      expect(th1.currentHash, equals(th2.currentHash));
    });

    test('different messages produce different hashes', () async {
      await transcriptHash.addMessage([1, 2, 3]);
      final hash1 = List<int>.from(transcriptHash.currentHash);
      await transcriptHash.addMessage([4, 5, 6]);
      final hash2 = List<int>.from(transcriptHash.currentHash);
      expect(hash1, isNot(equals(hash2)));
    });

    test('reset clears the hash', () async {
      await transcriptHash.addMessage([1, 2, 3]);
      expect(transcriptHash.currentHash, isNotEmpty);
      transcriptHash.reset();
      expect(transcriptHash.currentHash, isEmpty);
    });
  });

  group('HandshakeCoordinator transcript hash', () {
    test(
        'includes ClientHello in transcript hash after processClientHello',
        () async {
      final backend = _HashingMockBackend();
      final keyManager = KeyManager.forTest();
      final coordinator = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: keyManager,
      );

      await coordinator.generateKeys();

      final random = Uint8List(32);
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        random,
        Uint8List(0),
        [0x1301],
        [],
      );
      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);

      expect(coordinator.transcriptHash.currentHash, isEmpty);

      await coordinator.processClientHello(frame);

      expect(coordinator.transcriptHash.currentHash, isNotEmpty);
      expect(
        coordinator.transcriptHash.currentHash,
        isNot(equals(List<int>.filled(32, 0))),
      );
    });
  });
}

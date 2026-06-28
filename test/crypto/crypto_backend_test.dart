import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:test/test.dart';

import '../helpers/hex.dart';

void main() {
  late CryptoBackend backend;

  setUp(() {
    backend = DefaultCryptoBackend();
  });

  group('DefaultCryptoBackend', () {
    test('randomBytes returns correct length and non-zero', () async {
      final bytes = await backend.randomBytes(32);
      expect(bytes.length, equals(32));
      expect(bytes.any((b) => b != 0), isTrue);
    });

    test('sha256 known vector for empty string', () async {
      final result = await backend.sha256(<int>[]);
      final expected = hexDecode(
        'e3b0c44298fc1c149afbf4c8996fb924'
        '27ae41e4649b934ca495991b7852b855',
      );
      expect(result, equals(expected));
    });

    test('hkdfExpandLabel matches RFC 9001 test vector', () async {
      final initialSalt = hexDecode('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');
      final dcid = hexDecode('8394c8f03e515708');
      final initialSecret = await backend.hkdfExtract(
        Sha256(),
        _secretKey(initialSalt),
        _secretKey(dcid),
      );

      final clientInitialSecret = await backend.hkdfExpandLabel(
        Sha256(),
        initialSecret,
        'client in',
        <int>[],
        32,
      );

      final expected = hexDecode(
        'c00cf151ca5be075ed0ebfb5c80323c4'
        '2d6b7db67881289af4008f1f6c357aea',
      );
      expect(clientInitialSecret, equals(expected));
    });

    test('aeadEncrypt/aeadDecrypt round-trip AES-128-GCM', () async {
      final key = await backend.randomBytes(16);
      final nonce = await backend.randomBytes(12);
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);
      final aad = Uint8List.fromList([0xAB, 0xCD]);

      final encrypted = await backend.aeadEncrypt(
        Aes128Gcm(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );

      expect(encrypted.ciphertext.length, greaterThan(0));
      expect(encrypted.tag.length, equals(16));

      final decrypted = await backend.aeadDecrypt(
        Aes128Gcm(),
        _secretKey(key),
        nonce,
        encrypted.ciphertext,
        associatedData: aad,
      );

      expect(decrypted, equals(plaintext));
    });

    test('aeadEncrypt/aeadDecrypt round-trip ChaCha20-Poly1305', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = Uint8List.fromList([6, 7, 8, 9, 10]);
      final aad = Uint8List.fromList([0xEF, 0xFE]);

      final encrypted = await backend.aeadEncrypt(
        ChaCha20Poly1305(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );

      expect(encrypted.ciphertext.length, greaterThan(0));
      expect(encrypted.tag.length, equals(16));

      final decrypted = await backend.aeadDecrypt(
        ChaCha20Poly1305(),
        _secretKey(key),
        nonce,
        encrypted.ciphertext,
        associatedData: aad,
      );

      expect(decrypted, equals(plaintext));
    });

    test('x25519 shared secret equality', () async {
      final alice = await backend.x25519GenerateKeyPair();
      final bob = await backend.x25519GenerateKeyPair();

      final aliceSecret = await alice.secretKey;
      final alicePublic = await alice.publicKey;
      final bobSecret = await bob.secretKey;
      final bobPublic = await bob.publicKey;

      final sharedA = await backend.x25519SharedSecret(aliceSecret, bobPublic);
      final sharedB = await backend.x25519SharedSecret(bobSecret, alicePublic);

      expect(sharedA.extractSync(), equals(sharedB.extractSync()));
      expect(sharedA.extractSync().length, equals(32));
    });

    test('ed25519 sign/verify', () async {
      final keyPair = await backend.ed25519GenerateKeyPair();
      final privateKey = await keyPair.secretKey;
      final publicKey = await keyPair.publicKey;
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);

      final signature = await backend.ed25519Sign(privateKey, message);
      expect(signature.length, equals(64));

      final verified =
          await backend.ed25519Verify(publicKey, message, signature);
      expect(verified, isTrue);

      final tampered = Uint8List.fromList([1, 2, 3, 4, 6]);
      final verifiedTampered =
          await backend.ed25519Verify(publicKey, tampered, signature);
      expect(verifiedTampered, isFalse);
    });

    test('supportedCipherSuites returns expected list', () {
      final suites = backend.supportedCipherSuites();
      expect(suites, contains('TLS_AES_128_GCM_SHA256'));
      expect(suites, contains('TLS_AES_256_GCM_SHA384'));
      expect(suites, contains('TLS_CHACHA20_POLY1305_SHA256'));
      expect(suites.length, equals(3));
    });
  });
}

SecretKey _secretKey(List<int> bytes) => _TestSecretKey(bytes);

class _TestSecretKey implements SecretKey {
  final List<int> _bytes;
  _TestSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

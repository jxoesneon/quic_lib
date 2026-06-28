import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:test/test.dart';

void main() {
  late DefaultCryptoBackend backend;

  setUp(() {
    backend = DefaultCryptoBackend();
  });

  // --------------------------------------------------------------------------
  // cipher_suites.dart — concrete algorithm constants
  // --------------------------------------------------------------------------
  group('cipher_suites.dart algorithm constants', () {
    test('Aes128Gcm properties', () {
      final aead = Aes128Gcm();
      expect(aead.name, 'AES-128-GCM');
      expect(aead.keyLength, 16);
      expect(aead.nonceLength, 12);
      expect(aead.tagLength, 16);
    });

    test('Aes256Gcm properties', () {
      final aead = Aes256Gcm();
      expect(aead.name, 'AES-256-GCM');
      expect(aead.keyLength, 32);
      expect(aead.nonceLength, 12);
      expect(aead.tagLength, 16);
    });

    test('ChaCha20Poly1305 properties', () {
      final aead = ChaCha20Poly1305();
      expect(aead.name, 'ChaCha20-Poly1305');
      expect(aead.keyLength, 32);
      expect(aead.nonceLength, 12);
      expect(aead.tagLength, 16);
    });

    test('Sha256 properties', () {
      final hash = Sha256();
      expect(hash.name, 'SHA-256');
      expect(hash.hashLength, 32);
    });

    test('Sha384 properties', () {
      final hash = Sha384();
      expect(hash.name, 'SHA-384');
      expect(hash.hashLength, 48);
    });

    test('CipherSuite static constants have correct IDs', () {
      expect(CipherSuite.tlsAes128GcmSha256.id, 0x1301);
      expect(CipherSuite.tlsAes256GcmSha384.id, 0x1302);
      expect(CipherSuite.tlsChacha20Poly1305Sha256.id, 0x1303);
    });
  });

  // --------------------------------------------------------------------------
  // default_crypto_backend.dart — coverage gaps
  // --------------------------------------------------------------------------
  group('default_crypto_backend.dart coverage gaps', () {
    test('name returns "cryptography"', () {
      expect(backend.name, 'cryptography');
    });

    test('sha384 computes 48-byte digest', () async {
      final result = await backend.sha384(<int>[]);
      expect(result.length, 48);
    });

    test('hmac with Sha256 returns 32 bytes', () async {
      final key = _secretKey(List<int>.filled(32, 0));
      final result = await backend.hmac(Sha256(), key, [1, 2, 3]);
      expect(result.length, 32);
    });

    test('hmac with Sha384 returns 48 bytes', () async {
      final key = _secretKey(List<int>.filled(48, 0));
      final result = await backend.hmac(Sha384(), key, [1, 2, 3]);
      expect(result.length, 48);
    });

    test('hkdfExtract with Sha256 returns 32-byte PRK', () async {
      final salt = _secretKey([0, 1, 2, 3]);
      final ikm = _secretKey([4, 5, 6, 7]);
      final prk = await backend.hkdfExtract(Sha256(), salt, ikm);
      expect(prk.extractSync().length, 32);
    });

    test('hkdfExtract with Sha384 returns 48-byte PRK', () async {
      final salt = _secretKey([0, 1, 2, 3]);
      final ikm = _secretKey([4, 5, 6, 7]);
      final prk = await backend.hkdfExtract(Sha384(), salt, ikm);
      expect(prk.extractSync().length, 48);
    });

    test('hkdfExpand with Sha256 returns requested length', () async {
      final prk = _secretKey(List<int>.filled(32, 0));
      final result = await backend.hkdfExpand(Sha256(), prk, [1, 2, 3], 32);
      expect(result.length, 32);
    });

    test('hkdfExpand with Sha384 returns requested length', () async {
      final prk = _secretKey(List<int>.filled(48, 0));
      final result = await backend.hkdfExpand(Sha384(), prk, [1, 2, 3], 48);
      expect(result.length, 48);
    });

    test('aeadEncrypt with AES-256-GCM', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = [1, 2, 3, 4, 5];
      final aad = [0xAB, 0xCD];
      final result = await backend.aeadEncrypt(
        Aes256Gcm(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );
      expect(result.ciphertext.length, greaterThan(0));
      expect(result.tag.length, 16);
    });

    test('aeadDecrypt with AES-256-GCM round-trips', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = [1, 2, 3, 4, 5];
      final aad = [0xAB, 0xCD];
      final encrypted = await backend.aeadEncrypt(
        Aes256Gcm(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );
      final decrypted = await backend.aeadDecrypt(
        Aes256Gcm(),
        _secretKey(key),
        nonce,
        encrypted.ciphertext,
        associatedData: aad,
      );
      expect(decrypted, plaintext);
    });

    test('aeadEncrypt with ChaCha20-Poly1305', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = [6, 7, 8, 9, 10];
      final aad = [0xEF, 0xFE];
      final result = await backend.aeadEncrypt(
        ChaCha20Poly1305(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );
      expect(result.ciphertext.length, greaterThan(0));
      expect(result.tag.length, 16);
    });

    test('aeadDecrypt with ChaCha20-Poly1305 round-trips', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = [6, 7, 8, 9, 10];
      final aad = [0xEF, 0xFE];
      final encrypted = await backend.aeadEncrypt(
        ChaCha20Poly1305(),
        _secretKey(key),
        nonce,
        plaintext,
        associatedData: aad,
      );
      final decrypted = await backend.aeadDecrypt(
        ChaCha20Poly1305(),
        _secretKey(key),
        nonce,
        encrypted.ciphertext,
        associatedData: aad,
      );
      expect(decrypted, plaintext);
    });

    test('unsupported hash algorithm throws UnsupportedError', () async {
      final fakeHash = _FakeHash();
      final key = _secretKey([0]);
      await expectLater(
        backend.hmac(fakeHash, key, [1]),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('unsupported aead algorithm throws UnsupportedError', () async {
      final fakeAead = _FakeAead();
      final key = _secretKey([0]);
      await expectLater(
        backend.aeadEncrypt(fakeAead, key, [0], [1]),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('aeadDecrypt with too-short ciphertext throws ArgumentError',
        () async {
      final key = await backend.randomBytes(16);
      final nonce = await backend.randomBytes(12);
      await expectLater(
        backend.aeadDecrypt(
          Aes128Gcm(),
          _secretKey(key),
          nonce,
          [1, 2], // shorter than 16-byte tag
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('ecdsaP256GenerateKeyPair yields 65-byte uncompressed public key',
        () async {
      final kp = await backend.ecdsaP256GenerateKeyPair();
      final pub = await kp.publicKey;
      expect(pub.bytes.length, 65);
      expect(pub.bytes[0], 0x04);
    });

    test('ecdsaP256Verify returns false for bad signature', () async {
      final kp = await backend.ecdsaP256GenerateKeyPair();
      final pub = await kp.publicKey;
      final badSig = Uint8List(64);
      final verified = await backend.ecdsaP256Verify(pub, [1, 2, 3], badSig);
      expect(verified, isFalse);
    });

    test('rsaPkcs1Verify throws for invalid RSA key', () async {
      // SECURITY: Invalid keys must be rejected before verification to prevent
      // timing side channels. The method now throws rather than silently
      // swallowing parse errors.
      final badKey = _FakePublicKey();
      await expectLater(
        () => backend.rsaPkcs1Verify(
          badKey,
          Sha256(),
          [1, 2, 3],
          [4, 5, 6],
        ),
        throwsA(isA<Error>()),
      );
    });
  });
}

class _TestSecretKey implements SecretKey {
  final List<int> _bytes;
  _TestSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

SecretKey _secretKey(List<int> bytes) => _TestSecretKey(bytes);

class _FakeHash implements HashAlgorithm {
  @override
  int get hashLength => 32;

  @override
  String get name => 'FAKE-HASH';
}

class _FakeAead implements AeadAlgorithm {
  @override
  int get keyLength => 16;

  @override
  String get name => 'FAKE-AEAD';

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;
}

class _FakePublicKey implements PublicKey {
  @override
  List<int> get bytes => [1, 2, 3];
}

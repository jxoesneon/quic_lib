import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/helpers.dart' as crypto_helpers;
import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

import '../helpers/hex.dart';

void main() {
  late CryptoBackend backend;

  setUp(() {
    backend = DefaultCryptoBackend();
  });

  group('DefaultCryptoBackend', () {
    test('name is cryptography', () {
      expect(backend.name, equals('cryptography'));
    });

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

    test('sha384 known vector for empty string', () async {
      final result = await backend.sha384(<int>[]);
      final expected = hexDecode(
        '38b060a751ac96384cd9327eb1b1e36a'
        '21fdb71114be07434c0cc7bf63f6e1da'
        '274edebfe76f65fbd51ad2f14898b95b',
      );
      expect(result, equals(expected));
    });

    test('hmac with sha256', () async {
      final key = _secretKey(await backend.randomBytes(32));
      final data = Uint8List.fromList([1, 2, 3]);
      final mac = await backend.hmac(Sha256(), key, data);
      expect(mac.length, equals(32));
    });

    test('hmac with sha384', () async {
      final key = _secretKey(await backend.randomBytes(48));
      final data = Uint8List.fromList([4, 5, 6]);
      final mac = await backend.hmac(Sha384(), key, data);
      expect(mac.length, equals(48));
    });

    test('hkdfExtract produces deterministic output', () async {
      final salt = _secretKey([0x01, 0x02, 0x03]);
      final ikm = _secretKey([0x04, 0x05, 0x06]);
      final prk = await backend.hkdfExtract(Sha256(), salt, ikm);
      expect(prk.extractSync().length, equals(32));

      // Same inputs → same output
      final prk2 = await backend.hkdfExtract(Sha256(), salt, ikm);
      expect(prk.extractSync(), equals(prk2.extractSync()));
    });

    test('hkdfExpand exact block length', () async {
      final prk = _secretKey(List<int>.generate(32, (i) => i));
      final okm = await backend.hkdfExpand(Sha256(), prk, <int>[], 32);
      expect(okm.length, equals(32));
    });

    test('hkdfExpand multiple blocks', () async {
      final prk = _secretKey(List<int>.generate(32, (i) => i));
      final okm = await backend.hkdfExpand(Sha256(), prk, <int>[], 80);
      expect(okm.length, equals(80));
    });

    test('hkdfExpandLabel', () async {
      final secret = _secretKey(List<int>.generate(32, (i) => i));
      final okm = await backend.hkdfExpandLabel(
        Sha256(),
        secret,
        'test label',
        Uint8List.fromList([0xAB, 0xCD]),
        32,
      );
      expect(okm.length, equals(32));
    });

    test('hkdfExpandLabel with empty context', () async {
      final secret = _secretKey(List<int>.generate(32, (i) => i));
      final okm = await backend.hkdfExpandLabel(
        Sha256(),
        secret,
        'another label',
        <int>[],
        48,
      );
      expect(okm.length, equals(48));
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

    test('aeadEncrypt with AES-256-GCM', () async {
      final key = await backend.randomBytes(32);
      final nonce = await backend.randomBytes(12);
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5]);

      final encrypted = await backend.aeadEncrypt(
        Aes256Gcm(),
        _secretKey(key),
        nonce,
        plaintext,
      );

      expect(encrypted.ciphertext.length, greaterThan(0));
      expect(encrypted.tag.length, equals(16));

      final decrypted = await backend.aeadDecrypt(
        Aes256Gcm(),
        _secretKey(key),
        nonce,
        encrypted.ciphertext,
      );

      expect(decrypted, equals(plaintext));
    });

    test('aeadDecrypt throws on short ciphertext', () async {
      final key = await backend.randomBytes(16);
      final nonce = await backend.randomBytes(12);
      expect(
        () => backend.aeadDecrypt(
          Aes128Gcm(),
          _secretKey(key),
          nonce,
          [1, 2, 3],
        ),
        throwsA(isA<ArgumentError>()),
      );
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

    test('ecdsaP256GenerateKeyPair produces 65-byte uncompressed public key',
        () async {
      final keyPair = await backend.ecdsaP256GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      expect(publicKey.bytes.length, equals(65));
      expect(publicKey.bytes[0], equals(0x04));

      final secretKey = await keyPair.secretKey;
      expect(secretKey.extractSync().length, equals(32));
    });

    test('ecdsaP256Verify with valid signature', () async {
      final keyPair = await backend.ecdsaP256GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      final privateKey = await keyPair.secretKey;

      final message = Uint8List.fromList([1, 2, 3, 4, 5]);

      // Sign with pointycastle directly
      final domainParams = pc.ECCurve_prime256v1();
      final d = _decodeBigInt(privateKey.extractSync());
      final priv = pc.ECPrivateKey(d, domainParams);
      final signer = pc.ECDSASigner(pc.SHA256Digest(), null);
      final secureRandom = pc.SecureRandom('Fortuna')
        ..seed(pc.KeyParameter(Uint8List(32)));
      signer.init(true,
          pc.ParametersWithRandom(pc.PrivateKeyParameter(priv), secureRandom));
      final sig = signer.generateSignature(message) as pc.ECSignature;
      final signature = Uint8List(64);
      signature.setRange(0, 32, _encodeBigInt(sig.r, 32));
      signature.setRange(32, 64, _encodeBigInt(sig.s, 32));

      final verified =
          await backend.ecdsaP256Verify(publicKey, message, signature);
      expect(verified, isTrue);
    });

    test('ecdsaP256Verify rejects invalid signature', () async {
      final keyPair = await backend.ecdsaP256GenerateKeyPair();
      final publicKey = await keyPair.publicKey;

      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final badSignature = Uint8List(64);

      final verified =
          await backend.ecdsaP256Verify(publicKey, message, badSignature);
      expect(verified, isFalse);
    });

    test('ecdsaP256Verify throws on bad public key length', () async {
      final badKey = _SimplePublicKey([0x04, 0x01, 0x02]);
      expect(
        () => backend.ecdsaP256Verify(badKey, [1, 2, 3], Uint8List(64)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('ecdsaP256Verify throws on bad signature length', () async {
      final keyPair = await backend.ecdsaP256GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      expect(
        () => backend.ecdsaP256Verify(publicKey, [1, 2, 3], Uint8List(32)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('hmac throws on unsupported hash', () async {
      expect(
        () => backend
            .hmac(_MockHashAlgorithm(), _secretKey([1, 2, 3]), [4, 5, 6]),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('aeadEncrypt throws on unsupported AEAD', () async {
      expect(
        () => backend.aeadEncrypt(
          _MockAeadAlgorithm(),
          _secretKey([1, 2, 3]),
          [1, 2, 3],
          [4, 5, 6],
        ),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('rsaPkcs1Verify with valid signature (PKCS#1 key)', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey =
          _SimplePublicKey(_rsaPublicKeyToPkcs1(rsaKeyPair.publicKey));
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final signature = _rsaPkcs1Sign(rsaKeyPair.privateKey, message);

      final verified = await backend.rsaPkcs1Verify(
        publicKey,
        Sha256(),
        message,
        signature,
      );
      expect(verified, isTrue);
    });

    test('rsaPkcs1Verify with valid signature (X.509 key)', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey = _wrapRsaPublicKeyInX509(rsaKeyPair.publicKey);
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final signature = _rsaPkcs1Sign(rsaKeyPair.privateKey, message);

      final verified = await backend.rsaPkcs1Verify(
        publicKey,
        Sha256(),
        message,
        signature,
      );
      expect(verified, isTrue);
    });

    test('rsaPkcs1Verify with valid signature (SHA-384)', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey =
          _SimplePublicKey(_rsaPublicKeyToPkcs1(rsaKeyPair.publicKey));
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final signature = _rsaPkcs1SignSha384(rsaKeyPair.privateKey, message);

      final verified = await backend.rsaPkcs1Verify(
        publicKey,
        Sha384(),
        message,
        signature,
      );
      expect(verified, isTrue);
    });

    test('rsaPkcs1Verify rejects invalid signature', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey =
          _SimplePublicKey(_rsaPublicKeyToPkcs1(rsaKeyPair.publicKey));
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final badSignature = Uint8List(256);

      final verified = await backend.rsaPkcs1Verify(
        publicKey,
        Sha256(),
        message,
        badSignature,
      );
      expect(verified, isFalse);
    });

    test('rsaPkcs1Verify rejects bad signature format', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey =
          _SimplePublicKey(_rsaPublicKeyToPkcs1(rsaKeyPair.publicKey));
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      // Signature that is too short to be a valid RSA signature.
      final shortSignature = Uint8List(10);

      final verified = await backend.rsaPkcs1Verify(
        publicKey,
        Sha256(),
        message,
        shortSignature,
      );
      expect(verified, isFalse);
    });

    test('rsaPkcs1Verify throws on unsupported hash', () async {
      final rsaKeyPair = _generateRsaKeyPair();
      final publicKey =
          _SimplePublicKey(_rsaPublicKeyToPkcs1(rsaKeyPair.publicKey));

      expect(
        () => backend.rsaPkcs1Verify(
          publicKey,
          _MockHashAlgorithm(),
          [1, 2, 3],
          Uint8List(256),
        ),
        throwsA(isA<UnsupportedError>()),
      );
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

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

BigInt _decodeBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (var i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

Uint8List _encodeBigInt(BigInt value, int length) {
  final result = Uint8List(length);
  var temp = value;
  for (var i = length - 1; i >= 0; i--) {
    result[i] = (temp & BigInt.from(0xFF)).toInt();
    temp = temp >> 8;
  }
  return result;
}

({pc.RSAPublicKey publicKey, pc.RSAPrivateKey privateKey})
    _generateRsaKeyPair() {
  final keyGen = pc.RSAKeyGenerator();
  keyGen.init(
    pc.ParametersWithRandom(
      pc.RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12),
      pc.SecureRandom('Fortuna')
        ..seed(pc.KeyParameter(crypto_helpers.randomBytes(32))),
    ),
  );
  final pair = keyGen.generateKeyPair();
  final publicKey = pair.publicKey as pc.RSAPublicKey;
  final privateKey = pair.privateKey as pc.RSAPrivateKey;
  return (publicKey: publicKey, privateKey: privateKey);
}

PublicKey _wrapRsaPublicKeyInX509(pc.RSAPublicKey key) {
  final rsaPublicKeySeq = ASN1Sequence()
    ..add(ASN1Integer(key.modulus!))
    ..add(ASN1Integer(key.publicExponent!));

  final algorithmIdSeq = ASN1Sequence()
    ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1])) // rsaEncryption
    ..add(ASN1Null());

  final subjectPublicKeyInfo = ASN1Sequence()
    ..add(algorithmIdSeq)
    ..add(ASN1BitString(Uint8List.fromList(rsaPublicKeySeq.encodedBytes)));

  return _SimplePublicKey(subjectPublicKeyInfo.encodedBytes);
}

Uint8List _rsaPublicKeyToPkcs1(pc.RSAPublicKey key) {
  final rsaPublicKeySeq = ASN1Sequence()
    ..add(ASN1Integer(key.modulus!))
    ..add(ASN1Integer(key.publicExponent!));
  return Uint8List.fromList(rsaPublicKeySeq.encodedBytes);
}

Uint8List _rsaPkcs1Sign(pc.RSAPrivateKey privateKey, Uint8List message) {
  final signer = pc.Signer('SHA-256/RSA');
  signer.init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey),
        pc.SecureRandom('Fortuna')
          ..seed(pc.KeyParameter(crypto_helpers.randomBytes(32))),
      ));
  final sig = signer.generateSignature(message) as pc.RSASignature;
  return sig.bytes;
}

Uint8List _rsaPkcs1SignSha384(pc.RSAPrivateKey privateKey, Uint8List message) {
  final signer = pc.Signer('SHA-384/RSA');
  signer.init(
      true,
      pc.ParametersWithRandom(
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(privateKey),
        pc.SecureRandom('Fortuna')
          ..seed(pc.KeyParameter(crypto_helpers.randomBytes(32))),
      ));
  final sig = signer.generateSignature(message) as pc.RSASignature;
  return sig.bytes;
}

class _MockHashAlgorithm implements HashAlgorithm {
  @override
  String get name => 'MockHash';

  @override
  int get hashLength => 32;
}

class _MockAeadAlgorithm implements AeadAlgorithm {
  @override
  String get name => 'MockAEAD';

  @override
  int get tagLength => 16;

  @override
  int get keyLength => 16;

  @override
  int get nonceLength => 12;
}

import 'package:test/test.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'mock_crypto_backend.dart';

void main() {
  group('MockCryptoBackend defaults', () {
    late MockCryptoBackend backend;

    setUp(() {
      backend = MockCryptoBackend();
    });

    test('name is "mock"', () {
      expect(backend.name, 'mock');
    });

    test('supportedCipherSuites is empty', () {
      expect(backend.supportedCipherSuites(), isEmpty);
    });

    test('randomBytes returns list of given length', () async {
      final bytes = await backend.randomBytes(16);
      expect(bytes, hasLength(16));
    });

    test('sha256 returns empty list', () async {
      expect(await backend.sha256([1, 2, 3]), isEmpty);
    });

    test('sha384 returns empty list', () async {
      expect(await backend.sha384([1, 2, 3]), isEmpty);
    });

    test('hmac returns empty list', () async {
      expect(await backend.hmac(_FakeHash(), _FakeKey(), [1]), isEmpty);
    });

    test('hkdfExtract returns a SecretKey', () async {
      final key = await backend.hkdfExtract(_FakeHash(), _FakeKey(), _FakeKey());
      expect(await key.extractSync(), isEmpty);
    });

    test('hkdfExpand returns empty list', () async {
      expect(await backend.hkdfExpand(_FakeHash(), _FakeKey(), [], 32), isEmpty);
    });

    test('hkdfExpandLabel returns empty list', () async {
      expect(
        await backend.hkdfExpandLabel(_FakeHash(), _FakeKey(), 'label', [], 16),
        isEmpty,
      );
    });

    test('aeadEncrypt returns result with plaintext as ciphertext', () async {
      final result = await backend.aeadEncrypt(
        _FakeAead(),
        _FakeKey(),
        [0, 0, 0],
        [0x01, 0x02],
      );
      expect(result.ciphertext, [0x01, 0x02]);
    });

    test('aeadDecrypt returns empty list', () async {
      expect(
        await backend.aeadDecrypt(_FakeAead(), _FakeKey(), [], []),
        isEmpty,
      );
    });

    test('x25519GenerateKeyPair yields keys', () async {
      final kp = await backend.x25519GenerateKeyPair();
      expect(await kp.secretKey, isNotNull);
      expect(await kp.publicKey, isNotNull);
    });

    test('x25519SharedSecret returns a key', () async {
      final key = await backend.x25519SharedSecret(_FakeKey(), _FakePublicKey());
      expect(await key.extractSync(), isEmpty);
    });

    test('ed25519GenerateKeyPair yields keys', () async {
      final kp = await backend.ed25519GenerateKeyPair();
      expect(await kp.secretKey, isNotNull);
      expect(await kp.publicKey, isNotNull);
    });

    test('ed25519Sign returns empty list', () async {
      expect(await backend.ed25519Sign(_FakeKey(), [1]), isEmpty);
    });

    test('ed25519Verify returns true', () async {
      expect(
        await backend.ed25519Verify(_FakePublicKey(), [1], [2]),
        isTrue,
      );
    });

    test('ecdsaP256GenerateKeyPair yields keys', () async {
      final kp = await backend.ecdsaP256GenerateKeyPair();
      expect(await kp.secretKey, isNotNull);
      expect(await kp.publicKey, isNotNull);
    });

    test('ecdsaP256Verify returns true', () async {
      expect(
        await backend.ecdsaP256Verify(_FakePublicKey(), [1], [2]),
        isTrue,
      );
    });

    test('rsaPkcs1Verify returns true', () async {
      expect(
        await backend.rsaPkcs1Verify(
          _FakePublicKey(),
          _FakeHash(),
          [1],
          [2],
        ),
        isTrue,
      );
    });
  });
}

class _FakeHash implements HashAlgorithm {
  @override
  int get hashLength => 32;

  @override
  String get name => 'FAKE';
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

class _FakeKey implements SecretKey {
  @override
  List<int> extractSync() => <int>[];
}

class _FakePublicKey implements PublicKey {
  @override
  List<int> get bytes => <int>[];
}

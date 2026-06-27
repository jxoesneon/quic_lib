import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// Minimal test-only HashAlgorithm
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Minimal concrete CryptoBackend for testing using package:cryptography
// ---------------------------------------------------------------------------

class _TestCryptoBackend implements CryptoBackend {
  @override
  String get name => 'test';

  @override
  List<String> supportedCipherSuites() => ['TLS_AES_128_GCM_SHA256'];

  @override
  Future<List<int>> randomBytes(int length) async => Uint8List(length);

  @override
  Future<List<int>> sha256(List<int> data) async {
    final hash = await crypto.Sha256().hash(data);
    return hash.bytes;
  }

  @override
  Future<List<int>> sha384(List<int> data) async {
    final hash = await crypto.Sha384().hash(data);
    return hash.bytes;
  }

  @override
  Future<List<int>> hmac(HashAlgorithm hash, SecretKey key, List<int> data) {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> hkdfExtract(
    HashAlgorithm hash,
    SecretKey salt,
    SecretKey ikm,
  ) async {
    final hkdf = crypto.Hkdf(
      hmac: crypto.Hmac(crypto.Sha256()),
      outputLength: hash.hashLength,
    );
    final prk = await hkdf.deriveKey(
      secretKey: crypto.SecretKey(ikm.extractSync()),
      nonce: salt.extractSync(),
    );
    return SimpleSecretKey(prk.bytes);
  }

  @override
  Future<List<int>> hkdfExpand(
    HashAlgorithm hash,
    SecretKey prk,
    List<int> info,
    int length,
  ) async {
    final hkdf = crypto.Hkdf(
      hmac: crypto.Hmac(crypto.Sha256()),
      outputLength: length,
    );
    final result = await hkdf.deriveKey(
      secretKey: crypto.SecretKey(prk.extractSync()),
      info: info,
    );
    return result.bytes;
  }

  @override
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  ) async {
    final hkdfLabel = _buildHkdfLabel(label, context, length);
    return hkdfExpand(hash, secret, hkdfLabel, length);
  }

  static List<int> _buildHkdfLabel(String label, List<int> context, int length) {
    final fullLabel = 'tls13 $label';
    final labelBytes = utf8.encode(fullLabel);
    final result = BytesBuilder();
    result.addByte((length >> 8) & 0xFF);
    result.addByte(length & 0xFF);
    result.addByte(labelBytes.length);
    result.add(labelBytes);
    result.addByte(context.length);
    result.add(context);
    return result.toBytes();
  }

  @override
  Future<AeadResult> aeadEncrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> plaintext, {
    List<int>? associatedData,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<List<int>> aeadDecrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> ciphertext, {
    List<int>? associatedData,
  }) {
    throw UnimplementedError();
  }

  @override
  Future<KeyPair> x25519GenerateKeyPair() {
    throw UnimplementedError();
  }

  @override
  Future<SecretKey> x25519SharedSecret(
    SecretKey privateKey,
    PublicKey publicKey,
  ) {
    throw UnimplementedError();
  }

  @override
  Future<KeyPair> ed25519GenerateKeyPair() {
    throw UnimplementedError();
  }

  @override
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message) {
    throw UnimplementedError();
  }

  @override
  Future<bool> ed25519Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) {
    throw UnimplementedError();
  }

  @override
  Future<KeyPair> ecdsaP256GenerateKeyPair() {
    throw UnimplementedError();
  }

  @override
  Future<bool> ecdsaP256Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) {
    throw UnimplementedError();
  }

  @override
  Future<bool> rsaPkcs1Verify(
    PublicKey publicKey,
    HashAlgorithm hash,
    List<int> message,
    List<int> signature,
  ) {
    throw UnimplementedError();
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('InitialSecrets', () {
    test('derive produces different client and server secrets', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final backend = _TestCryptoBackend();
      final secrets = await InitialSecrets.derive(dcid, backend: backend);

      expect(
        secrets.clientSecret.extractSync(),
        isNot(equals(secrets.serverSecret.extractSync())),
      );
    });

    test('derive produces 32-byte secrets', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final backend = _TestCryptoBackend();
      final secrets = await InitialSecrets.derive(dcid, backend: backend);

      expect(secrets.clientSecret.extractSync().length, equals(32));
      expect(secrets.serverSecret.extractSync().length, equals(32));
    });

    test('derive is deterministic for same DCID', () async {
      final dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final backend = _TestCryptoBackend();
      final secrets1 = await InitialSecrets.derive(dcid, backend: backend);
      final secrets2 = await InitialSecrets.derive(dcid, backend: backend);

      expect(
        secrets1.clientSecret.extractSync(),
        equals(secrets2.clientSecret.extractSync()),
      );
      expect(
        secrets1.serverSecret.extractSync(),
        equals(secrets2.serverSecret.extractSync()),
      );
    });
  });
}

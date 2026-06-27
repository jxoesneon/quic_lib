import 'dart:typed_data';

import 'package:mocktail/mocktail.dart';

import 'package:dart_quic/src/crypto/crypto_backend.dart';

// ---------------------------------------------------------------------------
// Simple default implementations of related types
// ---------------------------------------------------------------------------

class _MockSecretKey implements SecretKey {
  final List<int> _bytes;
  _MockSecretKey([List<int>? bytes]) : _bytes = bytes ?? const <int>[];

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

class _MockPublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _MockPublicKey([List<int>? bytes]) : bytes = bytes ?? const <int>[];
}

class _MockKeyPair implements KeyPair {
  @override
  final Future<SecretKey> secretKey;
  @override
  final Future<PublicKey> publicKey;
  _MockKeyPair({List<int>? secret, List<int>? pub})
      : secretKey = Future.value(_MockSecretKey(secret)),
        publicKey = Future.value(_MockPublicKey(pub));
}

class _MockAeadResult implements AeadResult {
  @override
  final List<int> ciphertext;
  @override
  final List<int> tag;
  _MockAeadResult({List<int>? ciphertext, List<int>? tag})
      : ciphertext = ciphertext ?? const <int>[],
        tag = tag ?? const <int>[];
}

// ---------------------------------------------------------------------------
// Mock backend
// ---------------------------------------------------------------------------

/// A hand-rolled mock of [CryptoBackend] with sensible defaults for every
/// method.  Extends [Mock] from mocktail so that individual methods can be
/// stubbed or verified in tests when needed.
class MockCryptoBackend extends Mock implements CryptoBackend {
  @override
  String get name => 'mock';

  @override
  List<String> supportedCipherSuites() => <String>[];

  @override
  Future<List<int>> randomBytes(int length) => Future.value(Uint8List(length));

  @override
  Future<List<int>> sha256(List<int> data) => Future.value(<int>[]);

  @override
  Future<List<int>> sha384(List<int> data) => Future.value(<int>[]);

  @override
  Future<List<int>> hmac(HashAlgorithm hash, SecretKey key, List<int> data) =>
      Future.value(<int>[]);

  @override
  Future<SecretKey> hkdfExtract(
    HashAlgorithm hash,
    SecretKey salt,
    SecretKey ikm,
  ) =>
      Future.value(_MockSecretKey());

  @override
  Future<List<int>> hkdfExpand(
    HashAlgorithm hash,
    SecretKey prk,
    List<int> info,
    int length,
  ) =>
      Future.value(<int>[]);

  @override
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  ) =>
      Future.value(<int>[]);

  @override
  Future<AeadResult> aeadEncrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> plaintext, {
    List<int>? associatedData,
  }) =>
      Future.value(_MockAeadResult(ciphertext: plaintext));

  @override
  Future<List<int>> aeadDecrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> ciphertext, {
    List<int>? associatedData,
  }) =>
      Future.value(<int>[]);

  @override
  Future<KeyPair> x25519GenerateKeyPair() =>
      Future.value(_MockKeyPair());

  @override
  Future<SecretKey> x25519SharedSecret(
    SecretKey privateKey,
    PublicKey publicKey,
  ) =>
      Future.value(_MockSecretKey());

  @override
  Future<KeyPair> ed25519GenerateKeyPair() =>
      Future.value(_MockKeyPair());

  @override
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message) =>
      Future.value(<int>[]);

  @override
  Future<bool> ed25519Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) =>
      Future.value(true);

  @override
  Future<KeyPair> ecdsaP256GenerateKeyPair() =>
      Future.value(_MockKeyPair());

  @override
  Future<bool> ecdsaP256Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) =>
      Future.value(true);

  @override
  Future<bool> rsaPkcs1Verify(
    PublicKey publicKey,
    HashAlgorithm hash,
    List<int> message,
    List<int> signature,
  ) =>
      Future.value(true);
}

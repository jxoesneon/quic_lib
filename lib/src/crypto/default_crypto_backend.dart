import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/helpers.dart' as crypto_helpers;
import 'package:pointycastle/export.dart' as pc;

import 'cipher_suites.dart';
import 'crypto_backend.dart';

// ---------------------------------------------------------------------------
// Concrete wrapper types
// ---------------------------------------------------------------------------

class _SimpleSecretKey implements SecretKey {
  final List<int> _bytes;
  _SimpleSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

class _SimpleKeyPair implements KeyPair {
  final SecretKey _secretKey;
  final PublicKey _publicKey;
  _SimpleKeyPair(this._secretKey, this._publicKey);

  @override
  Future<SecretKey> get secretKey async => _secretKey;

  @override
  Future<PublicKey> get publicKey async => _publicKey;
}

/// Simple concrete implementation of [AeadResult].
class AeadResultImpl implements AeadResult {
  @override
  final List<int> ciphertext;
  @override
  final List<int> tag;

  AeadResultImpl(this.ciphertext, this.tag);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

crypto.SecretKey _toCryptoSecretKey(SecretKey key) =>
    crypto.SecretKey(key.extractSync());

crypto.HashAlgorithm _toCryptoHash(HashAlgorithm hash) {
  if (hash is Sha256) return crypto.Sha256();
  if (hash is Sha384) return crypto.Sha384();
  throw UnsupportedError('Unsupported hash algorithm: ${hash.name}');
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

pc.RSAPublicKey _parseRsaPublicKey(List<int> bytes) {
  final parser = ASN1Parser(Uint8List.fromList(bytes));
  final top = parser.nextObject();
  if (top is ASN1Sequence) {
    // PKCS#1 RSAPublicKey: SEQUENCE { modulus, publicExponent }
    if (top.elements.length == 2 && top.elements[0] is ASN1Integer) {
      final modulus = (top.elements[0] as ASN1Integer).valueAsBigInteger;
      final exponent = (top.elements[1] as ASN1Integer).valueAsBigInteger;
      return pc.RSAPublicKey(modulus, exponent);
    }
    // X.509 SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    if (top.elements.length == 2 && top.elements[1] is ASN1BitString) {
      final bitString = top.elements[1] as ASN1BitString;
      final innerParser = ASN1Parser(bitString.contentBytes());
      final innerSeq = innerParser.nextObject() as ASN1Sequence;
      final modulus = (innerSeq.elements[0] as ASN1Integer).valueAsBigInteger;
      final exponent = (innerSeq.elements[1] as ASN1Integer).valueAsBigInteger;
      return pc.RSAPublicKey(modulus, exponent);
    }
  }
  throw ArgumentError('Unable to parse RSA public key');
}

// ---------------------------------------------------------------------------
// DefaultCryptoBackend
// ---------------------------------------------------------------------------

/// Default implementation of [CryptoBackend] using
/// `package:cryptography` and `package:pointycastle`.
class DefaultCryptoBackend implements CryptoBackend {
  final _sha256 = crypto.Sha256();
  final _sha384 = crypto.Sha384();
  final _x25519 = crypto.X25519();
  final _ed25519 = crypto.Ed25519();

  @override
  String get name => 'cryptography';

  @override
  List<String> supportedCipherSuites() => const [
        'TLS_AES_128_GCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
      ];

  // -------------------------------------------------------------------------
  // Random bytes
  // -------------------------------------------------------------------------

  @override
  Future<List<int>> randomBytes(int length) async {
    return crypto_helpers.randomBytes(length);
  }

  // -------------------------------------------------------------------------
  // Hashes and HMAC
  // -------------------------------------------------------------------------

  @override
  Future<List<int>> sha256(List<int> data) async {
    final hash = await _sha256.hash(data);
    return hash.bytes;
  }

  @override
  Future<List<int>> sha384(List<int> data) async {
    final hash = await _sha384.hash(data);
    return hash.bytes;
  }

  @override
  Future<List<int>> hmac(
    HashAlgorithm hash,
    SecretKey key,
    List<int> data,
  ) async {
    final hmac = crypto.Hmac(_toCryptoHash(hash));
    final mac = await hmac.calculateMac(
      data,
      secretKey: _toCryptoSecretKey(key),
    );
    return mac.bytes;
  }

  // -------------------------------------------------------------------------
  // HKDF (RFC 5869)
  // -------------------------------------------------------------------------

  @override
  Future<SecretKey> hkdfExtract(
    HashAlgorithm hash,
    SecretKey salt,
    SecretKey ikm,
  ) async {
    final h = crypto.Hmac(_toCryptoHash(hash));
    final saltBytes = salt.extractSync();
    final ikmBytes = ikm.extractSync();
    final mac = await h.calculateMac(
      ikmBytes,
      secretKey: crypto.SecretKey(saltBytes),
    );
    return _SimpleSecretKey(mac.bytes);
  }

  @override
  Future<List<int>> hkdfExpand(
    HashAlgorithm hash,
    SecretKey prk,
    List<int> info,
    int length,
  ) async {
    final h = crypto.Hmac(_toCryptoHash(hash));
    final hashLen = hash.hashLength;
    final n = (length + hashLen - 1) ~/ hashLen;
    final result = Uint8List(length);
    var t = <int>[];
    final prkCrypto = _toCryptoSecretKey(prk);

    for (var i = 1; i <= n; i++) {
      final sink = await h.newMacSink(secretKey: prkCrypto);
      sink.add(t);
      sink.add(info);
      sink.add([i]);
      sink.close();
      final mac = await sink.mac();
      t = mac.bytes;
      final offset = (i - 1) * hashLen;
      final bytesToCopy =
          (offset + t.length <= length) ? t.length : length - offset;
      result.setRange(offset, offset + bytesToCopy, t);
    }
    return result;
  }

  @override
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  ) async {
    final fullLabel = 'tls13 $label';
    final labelBytes = Uint8List.fromList(fullLabel.codeUnits);
    final contextBytes = Uint8List.fromList(context);

    final builder = BytesBuilder();
    builder.addByte((length >> 8) & 0xFF);
    builder.addByte(length & 0xFF);
    builder.addByte(labelBytes.length);
    builder.add(labelBytes);
    builder.addByte(contextBytes.length);
    builder.add(contextBytes);

    return hkdfExpand(hash, secret, builder.toBytes(), length);
  }

  // -------------------------------------------------------------------------
  // AEAD
  // -------------------------------------------------------------------------

  crypto.Cipher _getCipher(AeadAlgorithm aead) {
    if (aead is Aes128Gcm) return crypto.AesGcm.with128bits();
    if (aead is Aes256Gcm) return crypto.AesGcm.with256bits();
    if (aead is ChaCha20Poly1305) return crypto.Chacha20.poly1305Aead();
    throw UnsupportedError('Unsupported AEAD: ${aead.name}');
  }

  @override
  Future<AeadResult> aeadEncrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> plaintext, {
    List<int>? associatedData,
  }) async {
    final cipher = _getCipher(aead);
    final secretBox = await cipher.encrypt(
      plaintext,
      secretKey: _toCryptoSecretKey(key),
      nonce: nonce,
      aad: associatedData ?? const [],
    );

    final combined = Uint8List(
      secretBox.cipherText.length + secretBox.mac.bytes.length,
    );
    combined.setRange(0, secretBox.cipherText.length, secretBox.cipherText);
    combined.setRange(
      secretBox.cipherText.length,
      combined.length,
      secretBox.mac.bytes,
    );

    return AeadResultImpl(combined, secretBox.mac.bytes);
  }

  @override
  Future<List<int>> aeadDecrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> ciphertext, {
    List<int>? associatedData,
  }) async {
    final cipher = _getCipher(aead);
    final tagLength = aead.tagLength;
    if (ciphertext.length < tagLength) {
      throw ArgumentError('Ciphertext too short to contain authentication tag');
    }

    final cipherTextOnly = ciphertext.sublist(0, ciphertext.length - tagLength);
    final tag = ciphertext.sublist(ciphertext.length - tagLength);

    final secretBox = crypto.SecretBox(
      cipherTextOnly,
      nonce: nonce,
      mac: crypto.Mac(tag),
    );

    return cipher.decrypt(
      secretBox,
      secretKey: _toCryptoSecretKey(key),
      aad: associatedData ?? const [],
    );
  }

  // -------------------------------------------------------------------------
  // Key exchange (X25519)
  // -------------------------------------------------------------------------

  @override
  Future<KeyPair> x25519GenerateKeyPair() async {
    final keyPair = await _x25519.newKeyPair();
    final secretBytes = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    return _SimpleKeyPair(
      _SimpleSecretKey(secretBytes),
      _SimplePublicKey(publicKey.bytes),
    );
  }

  @override
  Future<SecretKey> x25519SharedSecret(
    SecretKey privateKey,
    PublicKey publicKey,
  ) async {
    final seed = privateKey.extractSync();
    final keyPair = await _x25519.newKeyPairFromSeed(seed);
    final remotePublicKey = crypto.SimplePublicKey(
      publicKey.bytes,
      type: crypto.KeyPairType.x25519,
    );
    final shared = await _x25519.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: remotePublicKey,
    );
    final bytes = await shared.extractBytes();
    return _SimpleSecretKey(bytes);
  }

  // -------------------------------------------------------------------------
  // Signatures (Ed25519)
  // -------------------------------------------------------------------------

  @override
  Future<KeyPair> ed25519GenerateKeyPair() async {
    final keyPair = await _ed25519.newKeyPair();
    final secretBytes = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();
    return _SimpleKeyPair(
      _SimpleSecretKey(secretBytes),
      _SimplePublicKey(publicKey.bytes),
    );
  }

  @override
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message) async {
    final seed = privateKey.extractSync();
    final keyPair = await _ed25519.newKeyPairFromSeed(seed);
    final signature = await _ed25519.sign(message, keyPair: keyPair);
    return signature.bytes;
  }

  @override
  Future<bool> ed25519Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) async {
    final cryptoPublicKey = crypto.SimplePublicKey(
      publicKey.bytes,
      type: crypto.KeyPairType.ed25519,
    );
    final sig = crypto.Signature(
      signature,
      publicKey: cryptoPublicKey,
    );
    return _ed25519.verify(message, signature: sig);
  }

  // -------------------------------------------------------------------------
  // ECDSA (P-256)
  // -------------------------------------------------------------------------

  @override
  Future<KeyPair> ecdsaP256GenerateKeyPair() async {
    final domainParams = pc.ECCurve_prime256v1();
    final keyGenerator = pc.ECKeyGenerator();
    final params = pc.ECKeyGeneratorParameters(domainParams);
    final random = pc.FortunaRandom();
    final seed = crypto_helpers.randomBytes(32);
    random.seed(pc.KeyParameter(seed));
    keyGenerator.init(pc.ParametersWithRandom(params, random));
    final keyPair = keyGenerator.generateKeyPair();

    final privateKey = keyPair.privateKey as pc.ECPrivateKey;
    final publicKey = keyPair.publicKey as pc.ECPublicKey;

    final dBytes = _encodeBigInt(privateKey.d!, 32);

    final q = publicKey.Q!;
    final x = q.x!.toBigInteger()!;
    final y = q.y!.toBigInteger()!;
    final xBytes = _encodeBigInt(x, 32);
    final yBytes = _encodeBigInt(y, 32);
    final pubBytes = Uint8List(65);
    pubBytes[0] = 0x04;
    pubBytes.setRange(1, 33, xBytes);
    pubBytes.setRange(33, 65, yBytes);

    return _SimpleKeyPair(
      _SimpleSecretKey(dBytes),
      _SimplePublicKey(pubBytes),
    );
  }

  @override
  Future<bool> ecdsaP256Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) async {
    final domainParams = pc.ECCurve_prime256v1();

    // Expect uncompressed point: 0x04 || X || Y (65 bytes)
    final pubBytes = publicKey.bytes;
    if (pubBytes.length != 65 || pubBytes[0] != 0x04) {
      throw ArgumentError('Expected 65-byte uncompressed ECDSA P-256 public key');
    }

    final q = domainParams.curve.decodePoint(Uint8List.fromList(pubBytes));
    final pub = pc.ECPublicKey(q, domainParams);

    // Expect raw signature: r || s (64 bytes)
    if (signature.length != 64) {
      throw ArgumentError('Expected 64-byte raw ECDSA P-256 signature');
    }
    final r = _decodeBigInt(signature.sublist(0, 32));
    final s = _decodeBigInt(signature.sublist(32, 64));
    final sig = pc.ECSignature(r, s);

    final signer = pc.ECDSASigner(pc.SHA256Digest(), null);
    signer.init(false, pc.PublicKeyParameter(pub));
    return signer.verifySignature(Uint8List.fromList(message), sig);
  }

  // -------------------------------------------------------------------------
  // RSA signatures
  // -------------------------------------------------------------------------

  @override
  Future<bool> rsaPkcs1Verify(
    PublicKey publicKey,
    HashAlgorithm hash,
    List<int> message,
    List<int> signature,
  ) async {
    // SECURITY: Parse key and initialise signer OUTSIDE the try block to
    // prevent a timing side channel that would reveal whether the key or the
    // signature is invalid. Only signature-format errors are caught.
    final rsaKey = _parseRsaPublicKey(publicKey.bytes);
    final digestName = switch (hash) {
      Sha256() => 'SHA-256',
      Sha384() => 'SHA-384',
      _ => throw UnsupportedError('Unsupported RSA hash: ${hash.name}'),
    };
    final signer = pc.Signer('$digestName/RSA');
    signer.init(false, pc.PublicKeyParameter(rsaKey));

    try {
      return signer.verifySignature(
        Uint8List.fromList(message),
        pc.RSASignature(Uint8List.fromList(signature)),
      );
    } catch (_) {
      // Signature format is invalid (e.g. wrong length).
      return false;
    }
  }
}

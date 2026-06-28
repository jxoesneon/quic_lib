import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:test/test.dart';

/// Helpers to build DER-encoded ASN.1 structures for testing.
Uint8List _seq(List<Uint8List> children) => _tagged(0x30, _concat(children));
Uint8List _set(List<Uint8List> children) => _tagged(0x31, _concat(children));
Uint8List _int(int value) {
  final bytes = <int>[];
  var v = value;
  do {
    bytes.insert(0, v & 0xFF);
    v >>= 8;
  } while (v > 0);
  if (bytes.isNotEmpty && (bytes[0] & 0x80) != 0) {
    bytes.insert(0, 0);
  }
  return _tagged(0x02, bytes);
}

Uint8List _oid(List<int> bytes) => _tagged(0x06, bytes);
Uint8List _bitString(List<int> bytes) {
  final content = [0x00, ...bytes]; // unused bits count
  return _tagged(0x03, content);
}

Uint8List _utc(String s) => _tagged(0x17, s.codeUnits);
Uint8List _genTime(String s) => _tagged(0x18, s.codeUnits);
Uint8List _utf8(String s) => _tagged(0x0C, s.codeUnits);

Uint8List _concat(List<Uint8List> lists) {
  final builder = BytesBuilder();
  for (final l in lists) {
    builder.add(l);
  }
  return builder.toBytes();
}

Uint8List _tagged(int tag, List<int> content) {
  final len = content.length;
  final builder = BytesBuilder();
  builder.addByte(tag);
  if (len < 128) {
    builder.addByte(len);
  } else if (len < 256) {
    builder.addByte(0x81);
    builder.addByte(len);
  } else {
    builder.addByte(0x82);
    builder.addByte((len >> 8) & 0xFF);
    builder.addByte(len & 0xFF);
  }
  builder.add(content);
  return builder.toBytes();
}

Uint8List _context(int number, Uint8List content) {
  final tag = 0xA0 | number;
  return _tagged(tag, content);
}

/// Builds a minimal DER-encoded X.509 certificate.
Uint8List _buildMinimalCert({
  List<int>? sigAlgOid,
  bool useGenTime = false,
  bool omitVersion = false,
}) {
  final oidSig = _oid(sigAlgOid ?? [0x2b, 0x65, 0x70]);
  final oidCommonName = _oid([0x55, 0x04, 0x03]);

  final version = _context(0, _int(2));
  final serial = _int(1);
  final sigAlg = _seq([oidSig]);
  final name = _seq([
    _set([
      _seq([oidCommonName, _utf8('test-issuer')])
    ])
  ]);
  final validity = _seq([
    _utc('250101000000Z'),
    if (useGenTime) _genTime('20260101000000Z') else _utc('260101000000Z'),
  ]);
  final subject = _seq([
    _set([
      _seq([oidCommonName, _utf8('test-subject')])
    ])
  ]);
  final spki = _seq([
    _seq([
      _oid([0x2b, 0x65, 0x70])
    ]),
    _bitString([0xAA, 0xBB]),
  ]);

  final tbsChildren = <Uint8List>[
    if (!omitVersion) version,
    serial,
    sigAlg,
    name,
    validity,
    subject,
    spki,
  ];
  final tbs = _seq(tbsChildren);

  final sigValue = _bitString([0xCC, 0xDD, 0xEE]);

  return _seq([tbs, sigAlg, sigValue]);
}

void main() {
  group('parseX509 with real DER structures', () {
    test('parses a minimal valid certificate', () {
      final cert = parseX509(_buildMinimalCert());
      expect(cert.signatureAlgorithm, equals('ed25519'));
      expect(cert.signatureValue, equals([0xCC, 0xDD, 0xEE]));
      expect(cert.notBefore, equals(DateTime(2025, 1, 1, 0, 0, 0)));
      expect(cert.notAfter, equals(DateTime(2026, 1, 1, 0, 0, 0)));
      expect(cert.subjectPublicKeyInfo, isNotEmpty);
    });

    test('parses certificate with GeneralizedTime', () {
      final cert = parseX509(_buildMinimalCert(useGenTime: true));
      expect(cert.notAfter, equals(DateTime(2026, 1, 1, 0, 0, 0)));
    });

    test('parses certificate without version', () {
      final cert = parseX509(_buildMinimalCert(omitVersion: true));
      expect(cert.signatureAlgorithm, equals('ed25519'));
    });

    test('throws for invalid TBS certificate tag', () {
      final oidEd25519 = _oid([0x2b, 0x65, 0x70]);
      final sigAlg = _seq([oidEd25519]);
      final sigValue = _bitString([0xCC]);
      final badCert = _seq([_int(1), sigAlg, sigValue]);
      expect(() => parseX509(badCert), throwsFormatException);
    });

    test('handles unknown OID as unknown algorithm', () {
      final cert = parseX509(_buildMinimalCert(
          sigAlgOid: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x99]));
      expect(cert.signatureAlgorithm, equals('unknown'));
    });
  });

  group('parseX509 error paths', () {
    test('throws for empty input', () {
      expect(() => parseX509([]), throwsFormatException);
    });

    test('throws for non-SEQUENCE tag', () {
      expect(() => parseX509([0x01, 0x00]), throwsFormatException);
    });
  });

  group('verifyX509Signature algorithm routing', () {
    test('routes ecdsaP256 to backend', () async {
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02],
        signatureAlgorithm: 'ecdsaP256',
        signatureValue: [0x01],
        issuer: [],
        subject: [],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: [],
      );
      final pubKey = _SimplePublicKey([0x01]);
      final backend = _RecordingBackend();
      await verifyX509Signature(cert, pubKey, backend);
      expect(backend.lastAlgorithm, equals('ecdsaP256'));
    });

    test('routes rsaPkcs1Sha256 to backend', () async {
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02],
        signatureAlgorithm: 'rsaPkcs1Sha256',
        signatureValue: [0x01],
        issuer: [],
        subject: [],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: [],
      );
      final pubKey = _SimplePublicKey([0x01]);
      final backend = _RecordingBackend();
      await verifyX509Signature(cert, pubKey, backend);
      expect(backend.lastAlgorithm, equals('rsaPkcs1Sha256'));
    });

    test('routes rsaPkcs1Sha384 to backend', () async {
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02],
        signatureAlgorithm: 'rsaPkcs1Sha384',
        signatureValue: [0x01],
        issuer: [],
        subject: [],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: [],
      );
      final pubKey = _SimplePublicKey([0x01]);
      final backend = _RecordingBackend();
      await verifyX509Signature(cert, pubKey, backend);
      expect(backend.lastAlgorithm, equals('rsaPkcs1Sha384'));
    });
  });
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

class _RecordingBackend implements CryptoBackend {
  String? lastAlgorithm;

  @override
  String get name => 'recording';

  @override
  List<String> supportedCipherSuites() => [];

  @override
  Future<List<int>> randomBytes(int length) async => [];

  @override
  Future<List<int>> sha256(List<int> data) async => [];

  @override
  Future<List<int>> sha384(List<int> data) async => [];

  @override
  Future<List<int>> hmac(
          HashAlgorithm hash, SecretKey key, List<int> data) async =>
      [];

  @override
  Future<SecretKey> hkdfExtract(
          HashAlgorithm hash, SecretKey salt, SecretKey ikm) async =>
      _SimpleSecretKey([]);

  @override
  Future<List<int>> hkdfExpand(HashAlgorithm hash, SecretKey prk,
          List<int> info, int length) async =>
      [];

  @override
  Future<List<int>> hkdfExpandLabel(HashAlgorithm hash, SecretKey secret,
          String label, List<int> context, int length) async =>
      [];

  @override
  Future<AeadResult> aeadEncrypt(AeadAlgorithm aead, SecretKey key,
          List<int> nonce, List<int> plaintext,
          {List<int>? associatedData}) async =>
      _SimpleAeadResult([], []);

  @override
  Future<Uint8List> aeadDecrypt(AeadAlgorithm aead, SecretKey key,
          List<int> nonce, List<int> ciphertext,
          {List<int>? associatedData}) async =>
      Uint8List(0);

  @override
  Future<bool> ed25519Verify(
      PublicKey publicKey, List<int> message, List<int> signature) async {
    lastAlgorithm = 'ed25519';
    return true;
  }

  @override
  Future<bool> ecdsaP256Verify(
      PublicKey publicKey, List<int> message, List<int> signature) async {
    lastAlgorithm = 'ecdsaP256';
    return true;
  }

  @override
  Future<bool> rsaPkcs1Verify(PublicKey publicKey, HashAlgorithm hash,
      List<int> message, List<int> signature) async {
    lastAlgorithm = hash is Sha256 ? 'rsaPkcs1Sha256' : 'rsaPkcs1Sha384';
    return true;
  }

  @override
  Future<KeyPair> x25519GenerateKeyPair() async =>
      _SimpleKeyPair(_SimpleSecretKey([]), _SimplePublicKey([]));

  @override
  Future<SecretKey> x25519SharedSecret(
          SecretKey privateKey, PublicKey publicKey) async =>
      _SimpleSecretKey([]);

  @override
  Future<KeyPair> ed25519GenerateKeyPair() async =>
      _SimpleKeyPair(_SimpleSecretKey([]), _SimplePublicKey([]));

  @override
  Future<List<int>> ed25519Sign(
          SecretKey privateKey, List<int> message) async =>
      [];

  @override
  Future<List<int>> ecdsaP256Sign(
          SecretKey privateKey, List<int> message) async =>
      [];

  @override
  Future<KeyPair> ecdsaP256GenerateKeyPair() async =>
      _SimpleKeyPair(_SimpleSecretKey([]), _SimplePublicKey([]));
}

class _SimpleSecretKey implements SecretKey {
  final List<int> _bytes;
  _SimpleSecretKey(this._bytes);
  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

class _SimpleKeyPair implements KeyPair {
  final SecretKey _sk;
  final PublicKey _pk;
  _SimpleKeyPair(this._sk, this._pk);
  @override
  Future<SecretKey> get secretKey async => _sk;
  @override
  Future<PublicKey> get publicKey async => _pk;
}

class _SimpleAeadResult implements AeadResult {
  @override
  final List<int> ciphertext;
  @override
  final List<int> tag;
  _SimpleAeadResult(this.ciphertext, this.tag);
}

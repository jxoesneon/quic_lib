import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:quic_lib/src/libp2p/libp2p_certificate_generator.dart';
import 'package:quic_lib/src/libp2p/libp2p_tls_extension.dart';
import 'package:test/test.dart';

import '../helpers/mock_crypto_backend.dart';

// ---------------------------------------------------------------------------
// Local mock key implementations (private helpers from mock_crypto_backend.dart
// are not visible across library boundaries).
// ---------------------------------------------------------------------------
class _MockSecretKey implements SecretKey {
  final List<int> _bytes;
  _MockSecretKey(this._bytes);

  @override
  List<int> extractSync() => List<int>.from(_bytes);
}

class _MockPublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _MockPublicKey(this.bytes);
}

class _MockKeyPair implements KeyPair {
  @override
  final Future<SecretKey> secretKey;
  @override
  final Future<PublicKey> publicKey;

  _MockKeyPair({required List<int> secret, required List<int> pub})
      : secretKey = Future.value(_MockSecretKey(secret)),
        publicKey = Future.value(_MockPublicKey(pub));
}

// ---------------------------------------------------------------------------
// Test-specific mock backend with deterministic ECDSA P-256 output
// ---------------------------------------------------------------------------
class _TestCertificateCryptoBackend extends MockCryptoBackend {
  static final _ephemeralPublicKey = Uint8List.fromList([
    0x04, // uncompressed point format
    ...List<int>.generate(32, (i) => i),
    ...List<int>.generate(32, (i) => 31 - i),
  ]);

  static final _ecdsaSignature = Uint8List.fromList([
    ...List<int>.generate(32, (i) => 0xAA),
    ...List<int>.generate(32, (i) => 0xBB),
  ]);

  static final _ed25519Signature = Uint8List.fromList(
    List<int>.generate(64, (i) => 0xCC),
  );

  @override
  Future<KeyPair> ecdsaP256GenerateKeyPair() => Future.value(
        _MockKeyPair(
          secret: List<int>.generate(32, (i) => 0xDD),
          pub: _ephemeralPublicKey,
        ),
      );

  @override
  Future<List<int>> ecdsaP256Sign(SecretKey privateKey, List<int> message) =>
      Future.value(_ecdsaSignature);

  @override
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message) =>
      Future.value(_ed25519Signature);
}

void main() {
  group('Libp2pCertificateGenerator', () {
    late _TestCertificateCryptoBackend backend;
    late Libp2pCertificateGenerator generator;
    late SecretKey hostIdentityKey;
    late List<int> hostPublicKeyBytes;

    setUp(() async {
      backend = _TestCertificateCryptoBackend();
      generator = Libp2pCertificateGenerator(backend);
      hostIdentityKey = _MockSecretKey(List<int>.generate(32, (i) => 0xEE));
      hostPublicKeyBytes = List<int>.generate(32, (i) => 0xFF);
    });

    test('generates a certificate chain', () async {
      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
      );

      expect(chain.certs.length, equals(1));
      expect(chain.certs.first.rawBytes.isNotEmpty, isTrue);
    });

    test('generated certificate contains the libp2p extension', () async {
      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
      );

      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);

      expect(x509.extensions.containsKey(Libp2pExtension.oid), isTrue);

      final ext = parseLibp2pExtension(x509);
      expect(ext, isNotNull);
      expect(ext!.signedKey.publicKey.type, equals(Libp2pKeyType.ed25519));
      expect(ext.signedKey.publicKey.data, equals(hostPublicKeyBytes));
      // The signature covers libp2p-tls-handshake: || SubjectPublicKeyInfo DER.
      final spkiDer = x509.subjectPublicKeyInfo;
      final handshakeMessage = Uint8List.fromList([
        ...Uint8List.fromList('libp2p-tls-handshake:'.codeUnits),
        ...spkiDer,
      ]);
      expect(
        ext.signedKey.signature,
        equals(await backend.ed25519Sign(hostIdentityKey, handshakeMessage)),
      );
    });

    test('certificate is self-signed (issuer equals subject)', () async {
      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
      );

      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);

      // The generator uses empty RDN sequences for both issuer and subject,
      // so the raw DER bytes should be identical (both empty SEQUENCE).
      expect(x509.issuer, equals(x509.subject));
    });

    test('generated certificate has ECDSA P-256 signature algorithm', () async {
      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
      );

      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);

      expect(x509.signatureAlgorithm, equals('ecdsaP256'));
    });

    test('generated certificate contains the ephemeral public key', () async {
      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
      );

      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);

      // The SubjectPublicKeyInfo should contain the 65-byte uncompressed point.
      expect(x509.subjectPublicKeyInfo.length, greaterThanOrEqualTo(65));
    });

    test('validity window matches requested dates', () async {
      final notBefore = DateTime.utc(2025, 1, 1, 0, 0, 0);
      final notAfter = DateTime.utc(2025, 12, 31, 23, 59, 59);

      final chain = await generator.generate(
        hostIdentityPrivateKey: hostIdentityKey,
        hostPublicKeyBytes: hostPublicKeyBytes,
        notBefore: notBefore,
        notAfter: notAfter,
      );

      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);

      // UTCTime serialises without timezone info and the parser reconstructs
      // a local DateTime, so allow up to 24 hours of drift.
      expect(x509.notBefore.difference(notBefore).inSeconds.abs(),
          lessThan(86400));
      expect(
          x509.notAfter.difference(notAfter).inSeconds.abs(), lessThan(86400));
      expect(x509.notBefore.isBefore(x509.notAfter), isTrue);
    });
  });
}

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verifier.dart';
import 'package:test/test.dart';

void main() {
  late CryptoBackend backend;
  late CertificateVerifier verifier;

  setUp(() {
    backend = DefaultCryptoBackend();
    verifier = CertificateVerifier(backend);
  });

  group('CertificateVerifier.verifySignature', () {
    test('ed25519 round-trip (generate, sign, verify)', () async {
      final keyPair = await backend.ed25519GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      final secretKey = await keyPair.secretKey;
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);

      final signature = await backend.ed25519Sign(secretKey, message);
      expect(signature.length, equals(64));

      final result = await verifier.verifySignature(
        publicKey,
        message,
        Uint8List.fromList(signature),
        algorithm: 'ed25519',
      );
      expect(result, isTrue);
    });

    test('ed25519 rejects tampered message', () async {
      final keyPair = await backend.ed25519GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      final secretKey = await keyPair.secretKey;
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);

      final signature = await backend.ed25519Sign(secretKey, message);
      final tampered = Uint8List.fromList([1, 2, 3, 4, 6]);

      final result = await verifier.verifySignature(
        publicKey,
        tampered,
        Uint8List.fromList(signature),
        algorithm: 'ed25519',
      );
      expect(result, isFalse);
    });

    test('ecdsaP256 round-trip (generate, sign, verify)', () async {
      final keyPair = await backend.ecdsaP256GenerateKeyPair();
      final publicKey = await keyPair.publicKey;
      final secretKey = await keyPair.secretKey;
      final message = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);

      // Pointycastle ECDSA signing is not exposed on CryptoBackend, so we
      // verify the scaffold delegate by checking the algorithm switch.
      // The backend itself is tested in crypto_backend_test.dart; here we
      // only ensure the verifier forwards to the correct method.
      // For a true round-trip we would need a sign method on the backend.
      // Instead we assert that the verifier calls ecdsaP256Verify and the
      // mock backend (or real backend with a pre-computed valid signature)
      // behaves correctly.
      //
      // To keep this test self-contained with the *real* backend we generate
      // a deterministic raw signature (r||s) using pointycastle directly.
      // Note: this is test-only code and duplicates a small helper.
      final signature = await _ecdsaP256Sign(secretKey, message);

      final result = await verifier.verifySignature(
        publicKey,
        message,
        signature,
        algorithm: 'ecdsaP256',
      );
      expect(result, isTrue);
    });

    test('unsupported algorithm throws', () async {
      final pub = _SimplePublicKey([1, 2, 3]);
      final message = Uint8List(0);
      final signature = Uint8List(0);

      expect(
        verifier.verifySignature(
          pub,
          message,
          signature,
          algorithm: 'unknown',
        ),
        throwsUnsupportedError,
      );
    });
  });

  group('CertificateVerifier.verifyCertificateChain', () {
    test('returns true for empty chain (scaffold behaviour)', () {
      final trustedRoot = _SimplePublicKey([0xAA]);
      final result = verifier.verifyCertificateChain([], trustedRoot);
      expect(result, isTrue);
    });

    test('returns true for single-cert chain (scaffold behaviour)', () {
      final trustedRoot = _SimplePublicKey([0xBB]);
      final cert = CertificateMessage(entries: [
        CertificateEntry(certData: [0x01, 0x02]),
      ]);
      final result = verifier.verifyCertificateChain([cert], trustedRoot);
      expect(result, isTrue);
    });

    test('returns true for multi-cert chain (scaffold behaviour)', () {
      final trustedRoot = _SimplePublicKey([0xCC]);
      final chain = [
        CertificateMessage(entries: [
          CertificateEntry(certData: [0x01]),
        ]),
        CertificateMessage(entries: [
          CertificateEntry(certData: [0x02]),
        ]),
      ];
      final result = verifier.verifyCertificateChain(chain, trustedRoot);
      expect(result, isTrue);
    });
  });
}

// ---------------------------------------------------------------------------
// Helpers – minimal local implementations so this test file is self-contained
// ---------------------------------------------------------------------------

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

/// Generates a raw ECDSA P-256 signature (r || s, 64 bytes) using
/// pointycastle so the test can perform a full sign/verify round-trip
/// without requiring an `ecdsaP256Sign` method on [CryptoBackend].
Future<Uint8List> _ecdsaP256Sign(SecretKey secretKey, List<int> message) async {
  // ignore: avoid_dynamic_calls
  final domainParams = pc.ECCurve_prime256v1();
  final d = _decodeBigInt(secretKey.extractSync());
  final privateKey = pc.ECPrivateKey(d, domainParams);

  final signer =
      pc.ECDSASigner(pc.SHA256Digest(), pc.HMac(pc.SHA256Digest(), 64));
  final random = pc.FortunaRandom();
  random.seed(pc.KeyParameter(
      Uint8List.fromList(await _backendForTests.randomBytes(32))));
  signer.init(true,
      pc.ParametersWithRandom(pc.PrivateKeyParameter(privateKey), random));

  final sig =
      signer.generateSignature(Uint8List.fromList(message)) as pc.ECSignature;
  final result = Uint8List(64);
  result.setRange(0, 32, _encodeBigInt(sig.r, 32));
  result.setRange(32, 64, _encodeBigInt(sig.s, 32));
  return result;
}

final _backendForTests = DefaultCryptoBackend();

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

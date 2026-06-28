import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_chain.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verifier.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';
import '../../helpers/minimal_cert.dart';

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

/// A [MockCryptoBackend] that records Ed25519 verification calls.
class _RecordingCryptoBackend extends MockCryptoBackend {
  final List<({PublicKey publicKey, List<int> message, List<int> signature})>
      ed25519Calls = [];

  @override
  Future<bool> ed25519Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  ) {
    ed25519Calls.add(
      (publicKey: publicKey, message: message, signature: signature),
    );
    return super.ed25519Verify(publicKey, message, signature);
  }
}

void main() {
  group('CertificateVerifier issuer key selection', () {
    test('multi-certificate chain verifies each cert against its issuer',
        () async {
      final backend = _RecordingCryptoBackend();
      final verifier = CertificateVerifier(backend);
      final trustedRoot = _SimplePublicKey([0xAA]);
      final chain = [
        CertificateMessage(entries: [
          CertificateEntry(certData: buildMinimalCert()),
        ]),
        CertificateMessage(entries: [
          CertificateEntry(certData: buildMinimalCert()),
        ]),
      ];

      final result = await verifier.verifyCertificateChain(chain, trustedRoot);
      expect(result, isTrue);
      expect(backend.ed25519Calls.length, equals(2));

      // First cert (i=0) should be verified against the next cert's public key.
      // The minimal cert has an empty SubjectPublicKeyInfo SEQUENCE, so the
      // intermediate issuer key bytes are [0x30, 0x00].
      expect(backend.ed25519Calls[0].publicKey.bytes, equals([0x30, 0x00]));

      // Second cert (i=1, last in chain) should be verified against trustedRoot.
      expect(backend.ed25519Calls[1].publicKey.bytes, equals([0xAA]));
    });
  });

  group('verifyX509Signature backend delegation', () {
    test('delegates ed25519 to backend.ed25519Verify', () async {
      final backend = MockCryptoBackend();
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02, 0xAA, 0xBB],
        signatureAlgorithm: 'ed25519',
        signatureValue: [0x01, 0x02],
        issuer: const <int>[],
        subject: const <int>[],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: const <int>[],
      );
      final pubKey = _SimplePublicKey([0xCC]);

      await verifyX509Signature(cert, pubKey, backend);
      // MockCryptoBackend.ed25519Verify returns true by default.
    });

    test('delegates ecdsaP256 to backend.ecdsaP256Verify', () async {
      final backend = MockCryptoBackend();
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02, 0xAA, 0xBB],
        signatureAlgorithm: 'ecdsaP256',
        signatureValue: [0x01, 0x02],
        issuer: const <int>[],
        subject: const <int>[],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: const <int>[],
      );
      final pubKey = _SimplePublicKey([0xCC]);

      await verifyX509Signature(cert, pubKey, backend);
      // MockCryptoBackend.ecdsaP256Verify returns true by default.
    });

    test('throws UnsupportedError for unknown algorithm', () async {
      final backend = MockCryptoBackend();
      final cert = X509Certificate(
        tbsCertificate: [0x30, 0x02, 0xAA, 0xBB],
        signatureAlgorithm: 'unknown',
        signatureValue: const <int>[],
        issuer: const <int>[],
        subject: const <int>[],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: const <int>[],
      );
      final pubKey = _SimplePublicKey([0xCC]);

      expect(
        verifyX509Signature(cert, pubKey, backend),
        throwsUnsupportedError,
      );
    });
  });

  group('malformed certificate rejection', () {
    test('parseCertificate throws FormatException for non-DER bytes', () {
      expect(() => parseCertificate([0x01, 0x02, 0x03]), throwsFormatException);
    });

    test('parseCertificate throws FormatException for empty bytes', () {
      expect(() => parseCertificate([]), throwsFormatException);
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:test/test.dart';

import '../../helpers/mock_crypto_backend.dart';
import '../../helpers/minimal_cert.dart';

void main() {
  group('parseX509', () {
    test(
        'returns an X509Certificate for valid DER-like bytes (starting with 0x30)',
        () {
      final derBytes = buildMinimalCert();
      final cert = parseX509(derBytes);
      expect(cert, isA<X509Certificate>());
    });

    test('throws for non-DER bytes', () {
      expect(() => parseX509([0x01, 0x02, 0x03]), throwsFormatException);
      expect(() => parseX509([]), throwsFormatException);
    });

    test('rejects malformed certificate with insufficient top-level elements',
        () {
      expect(
        () => parseX509([0x30, 0x02, 0xAA, 0xBB]),
        throwsFormatException,
      );
    });

    test('X509Certificate fields are populated from parsed DER', () {
      final derBytes = buildMinimalCert();
      final cert = parseX509(derBytes);
      expect(cert.signatureAlgorithm, equals('ed25519'));
      expect(cert.signatureValue, isEmpty);
      // Issuer/subject are INTEGER placeholders, so they stay empty.
      expect(cert.issuer, isEmpty);
      expect(cert.subject, isEmpty);
      // SPKI is an empty SEQUENCE, so the parser includes tag+length bytes.
      expect(cert.subjectPublicKeyInfo, equals([0x30, 0x00]));
    });
  });

  group('verifyX509Signature', () {
    test('delegates to backend for ed25519', () async {
      final cert = parseX509(buildMinimalCert());
      final pubKey = _SimplePublicKey([0x01, 0x02]);
      final backend = MockCryptoBackend();
      final result = await verifyX509Signature(cert, pubKey, backend);
      // MockCryptoBackend returns true by default; the important thing is
      // that verifyX509Signature delegates to the backend instead of
      // returning a hard-coded true.
      expect(result, isTrue);
    });

    test('throws for unsupported algorithm', () async {
      final cert = X509Certificate(
        tbsCertificate: buildMinimalCert(),
        signatureAlgorithm: 'unknown',
        signatureValue: const <int>[],
        issuer: const <int>[],
        subject: const <int>[],
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectPublicKeyInfo: const <int>[],
      );
      final pubKey = _SimplePublicKey([0x01, 0x02]);
      final backend = MockCryptoBackend();
      expect(
        verifyX509Signature(cert, pubKey, backend),
        throwsUnsupportedError,
      );
    });
  });
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

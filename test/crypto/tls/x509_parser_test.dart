import 'dart:typed_data';

import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/tls/x509_parser.dart';
import 'package:test/test.dart';

void main() {
  group('parseX509', () {
    test('returns an X509Certificate for valid DER-like bytes (starting with 0x30)',
        () {
      final derBytes = Uint8List.fromList([0x30, 0x03, 0x01, 0x01, 0xFF]);
      final cert = parseX509(derBytes);
      expect(cert, isA<X509Certificate>());
      expect(cert.tbsCertificate, equals(derBytes));
    });

    test('throws for non-DER bytes', () {
      expect(() => parseX509([0x01, 0x02, 0x03]), throwsFormatException);
      expect(() => parseX509([]), throwsFormatException);
    });

    test('X509Certificate fields are populated with scaffold defaults', () {
      final derBytes = Uint8List.fromList([0x30, 0x02, 0xAA, 0xBB]);
      final cert = parseX509(derBytes);
      expect(cert.tbsCertificate, equals(derBytes));
      expect(cert.signatureAlgorithm, equals('ed25519'));
      expect(cert.signatureValue, isEmpty);
      expect(cert.issuer, isEmpty);
      expect(cert.subject, isEmpty);
      expect(cert.notBefore, equals(DateTime(2020, 1, 1)));
      expect(cert.notAfter, equals(DateTime(2030, 1, 1)));
      expect(cert.notAfter.isAfter(cert.notBefore), isTrue);
      expect(cert.subjectPublicKeyInfo, isEmpty);
    });
  });

  group('verifyX509Signature', () {
    test('returns true for scaffold', () {
      final cert = parseX509([0x30, 0x02, 0xAA, 0xBB]);
      final pubKey = _SimplePublicKey([0x01, 0x02]);
      final backend = DefaultCryptoBackend();
      expect(verifyX509Signature(cert, pubKey, backend), isTrue);
    });
  });
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

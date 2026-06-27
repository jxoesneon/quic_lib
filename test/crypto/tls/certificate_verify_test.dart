import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/crypto/tls/certificate_verify.dart';

void main() {
  group('CertificateVerify', () {
    test('serialize round-trip with parse', () {
      final signature = List<int>.generate(64, (i) => i % 256);
      final original = CertificateVerify(
        signatureScheme: CertificateVerify.ecdsaSecp256r1Sha256,
        signature: signature,
      );

      final serialized = original.serialize();
      final parsed = CertificateVerify.parse(serialized);

      expect(parsed.signatureScheme, equals(original.signatureScheme));
      expect(parsed.signature, equals(original.signature));
    });

    test('signature scheme preserved', () {
      final schemes = <int>[
        CertificateVerify.rsaPkcs1Sha256,
        CertificateVerify.rsaPkcs1Sha384,
        CertificateVerify.rsaPssRsaeSha256,
        CertificateVerify.rsaPssRsaeSha384,
        CertificateVerify.ecdsaSecp256r1Sha256,
        CertificateVerify.ecdsaSecp384r1Sha384,
        CertificateVerify.ed25519,
      ];

      for (final scheme in schemes) {
        final msg = CertificateVerify(
          signatureScheme: scheme,
          signature: [0xAB, 0xCD],
        );
        final serialized = msg.serialize();
        final parsed = CertificateVerify.parse(serialized);
        expect(parsed.signatureScheme, equals(scheme));
      }
    });

    test('signature bytes preserved', () {
      final signature = List<int>.generate(256, (i) => (i * 7 + 13) % 256);
      final original = CertificateVerify(
        signatureScheme: CertificateVerify.rsaPssRsaeSha256,
        signature: signature,
      );

      final serialized = original.serialize();
      final parsed = CertificateVerify.parse(serialized);

      expect(parsed.signature, equals(signature));
    });

    test('empty signature works', () {
      final original = CertificateVerify(
        signatureScheme: CertificateVerify.ed25519,
        signature: [],
      );

      final serialized = original.serialize();
      expect(serialized.length, equals(4));
      expect(serialized, equals(Uint8List.fromList([0x08, 0x07, 0x00, 0x00])));

      final parsed = CertificateVerify.parse(serialized);
      expect(parsed.signatureScheme, equals(CertificateVerify.ed25519));
      expect(parsed.signature, isEmpty);
    });
  });
}

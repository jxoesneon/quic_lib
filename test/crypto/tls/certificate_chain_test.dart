import 'package:quic_lib/src/crypto/tls/certificate_chain.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:test/test.dart';

void main() {
  group('CertificateInfo', () {
    test('parseCertificate returns a CertificateInfo', () {
      final info = parseCertificate([0x01, 0x02, 0x03]);
      expect(info.rawBytes, equals([0x01, 0x02, 0x03]));
      expect(info.notBefore, equals(DateTime(2020, 1, 1)));
      expect(info.notAfter, equals(DateTime(2030, 1, 1)));
    });

    test('isExpired detects expired certificate', () {
      final info = parseCertificate([]);
      expect(isExpired(info, DateTime(2035, 1, 1)), isTrue);
      expect(isExpired(info, DateTime(2025, 1, 1)), isFalse);
    });

    test('isSelfSigned returns true when subject == issuer', () {
      final info = CertificateInfo(
        rawBytes: const [],
        subjectPublicKey: const [],
        algorithm: 'ed25519',
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectName: 'CN=same',
        issuerName: 'CN=same',
      );
      expect(isSelfSigned(info), isTrue);
    });
  });

  group('CertificateChain', () {
    test('validateChain with valid chain returns true', () {
      final chain = CertificateChain([
        parseCertificate([0x01]),
        parseCertificate([0x02]),
      ]);
      expect(chain.validateChain(DateTime(2025, 1, 1)), isTrue);
    });

    test('validateChain with expired cert returns false', () {
      final chain = CertificateChain([
        parseCertificate([0x01]),
      ]);
      expect(chain.validateChain(DateTime(2035, 1, 1)), isFalse);
    });

    test('validateChain rejects unsupported algorithm', () {
      final chain = CertificateChain([
        CertificateInfo(
          rawBytes: const [],
          subjectPublicKey: const [],
          algorithm: 'unsupported',
          notBefore: DateTime(2020, 1, 1),
          notAfter: DateTime(2030, 1, 1),
          subjectName: 'CN=test',
        ),
      ]);
      expect(chain.validateChain(DateTime(2025, 1, 1)), isFalse);
    });
  });

  group('CertificateVerifier integration', () {
    test('verifyCertificateChain with empty chain returns true', () {
      final verifier = _MockVerifier();
      expect(verifier.verifyCertificateChain([]), isTrue);
    });

    test('verifyCertificateChain with valid entries returns true', () {
      final verifier = _MockVerifier();
      final cert = CertificateMessage(
        requestContext: [],
        entries: [
          CertificateEntry(certData: [0x01], extensions: []),
        ],
      );
      expect(verifier.verifyCertificateChain([cert]), isTrue);
    });
  });
}

class _MockVerifier {
  bool verifyCertificateChain(List<CertificateMessage> chain) {
    if (chain.isEmpty) return true;
    final infos = <CertificateInfo>[];
    for (final cert in chain) {
      for (final entry in cert.entries) {
        infos.add(parseCertificate(entry.certData));
      }
    }
    return CertificateChain(infos).validateChain(DateTime.now());
  }
}

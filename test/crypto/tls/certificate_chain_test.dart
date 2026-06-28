import 'package:dart_quic/src/crypto/tls/certificate_chain.dart';
import 'package:dart_quic/src/crypto/tls/certificate_message.dart';
import 'package:test/test.dart';

import '../../helpers/minimal_cert.dart';

void main() {
  group('CertificateInfo', () {
    test('parseCertificate returns a CertificateInfo', () {
      final raw = buildMinimalCert();
      final info = parseCertificate(raw);
      expect(info.rawBytes, equals(raw));
    });

    test('isExpired detects expired certificate', () {
      final info = parseCertificate(buildMinimalCert());
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
        parseCertificate(buildMinimalCert()),
        parseCertificate(buildMinimalCert()),
      ]);
      expect(chain.validateChain(DateTime(2025, 1, 1)), isTrue);
    });

    test('validateChain with expired cert returns false', () {
      final chain = CertificateChain([
        parseCertificate(buildMinimalCert()),
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
    test('verifyCertificateChain with empty chain returns false', () {
      final verifier = _MockVerifier();
      // SECURITY: Empty chains are never valid.
      expect(verifier.verifyCertificateChain([]), isFalse);
    });

    test('verifyCertificateChain with valid entries returns true', () {
      final verifier = _MockVerifier();
      final cert = CertificateMessage(
        requestContext: [],
        entries: [
          CertificateEntry(certData: buildMinimalCert(), extensions: []),
        ],
      );
      expect(verifier.verifyCertificateChain([cert]), isTrue);
    });
  });
}

class _MockVerifier {
  bool verifyCertificateChain(List<CertificateMessage> chain) {
    // SECURITY: Empty chains are never valid.
    if (chain.isEmpty) return false;
    final infos = <CertificateInfo>[];
    for (final cert in chain) {
      for (final entry in cert.entries) {
        infos.add(parseCertificate(entry.certData));
      }
    }
    return CertificateChain(infos).validateChain(DateTime.now());
  }
}

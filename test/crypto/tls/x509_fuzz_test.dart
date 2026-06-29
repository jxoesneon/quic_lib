import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:test/test.dart';

import '../../helpers/minimal_cert.dart';

/// Fuzz/error-path tests for the DER/X.509 parser.
///
/// Verifies that malformed certificates, missing extensions, invalid lengths,
/// and random byte streams are rejected with [FormatException] or
/// [ArgumentError] rather than returning bogus data or crashing.
void main() {
  group('parseX509 malformed input', () {
    test('throws for empty input', () {
      expect(() => parseX509([]), throwsFormatException);
    });

    test('throws for non-SEQUENCE tag', () {
      expect(
        () => parseX509(Uint8List.fromList([0x02, 0x01, 0x00])),
        throwsFormatException,
      );
    });

    test('throws for truncated top-level length', () {
      // SEQUENCE tag, then length that claims 100 bytes but only 2 follow.
      final bytes = Uint8List.fromList([0x30, 0x64, 0x00, 0x00]);
      expect(() => parseX509(bytes), throwsFormatException);
    });

    test('throws for indefinite length', () {
      final bytes = Uint8List.fromList([0x30, 0x80, 0x00, 0x00]);
      expect(() => parseX509(bytes), throwsFormatException);
    });

    test('throws for insufficient top-level elements', () {
      // Outer SEQUENCE with a single INTEGER child.
      final bytes = Uint8List.fromList([
        0x30,
        0x03,
        0x02,
        0x01,
        0x00,
      ]);
      expect(() => parseX509(bytes), throwsFormatException);
    });

    test('parses minimal cert and reports empty extensions', () {
      final cert = parseX509(buildMinimalCert());
      expect(cert, isA<X509Certificate>());
      expect(cert.extensions, isEmpty);
    });

    test('missing extensions yield empty map', () {
      // Build a minimal cert without the [3] extensions wrapper.
      final builder = BytesBuilder();
      final tbs = _buildTbsWithoutExtensions();
      final sigAlg = _buildSimpleSigAlg();
      final sigValue = _buildBitString([]);
      builder.addByte(0x30);
      final content = [tbs, sigAlg, sigValue].expand((x) => x).toList();
      builder.addByte(content.length);
      builder.add(content);
      final cert = parseX509(Uint8List.fromList(builder.toBytes()));
      expect(cert.extensions, isEmpty);
    });

    test('throws for malformed time inside validity', () {
      // Build a certificate whose notBefore time has a non-digit in the middle,
      // which causes int.parse on the month substring to fail.
      final tbs = _buildTbsWithInvalidTime();
      final sigAlg = _buildSimpleSigAlg();
      final sigValue = _buildBitString([]);
      final content = [tbs, sigAlg, sigValue].expand((x) => x).toList();
      final cert = Uint8List.fromList([
        0x30,
        content.length,
        ...content,
      ]);
      expect(() => parseX509(cert), throwsFormatException);
    });

    test('random byte streams are rejected cleanly', () {
      final random = Random(42);
      for (var i = 0; i < 300; i++) {
        final len = random.nextInt(128) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        try {
          parseX509(bytes);
        } on FormatException catch (_) {
          // Expected.
        } on ArgumentError catch (_) {
          // Expected.
        }
      }
    });

    test('throws for signature value BIT STRING with truncated length', () {
      final base = buildMinimalCert().toList();
      // Remove the last byte to corrupt the trailing BIT STRING.
      base.removeLast();
      expect(() => parseX509(Uint8List.fromList(base)), throwsFormatException);
    });
  });

  group('parseLibp2pExtension malformed input', () {
    test('returns null when extension is missing', () {
      final cert = parseX509(buildMinimalCert());
      expect(parseLibp2pExtension(cert), isNull);
    });

    test('returns null for malformed extension bytes', () {
      final cert = parseX509(buildMinimalCert());
      // Inject a garbage extension value without the proper SignedKey structure.
      final certWithBadExt = X509Certificate(
        tbsCertificate: cert.tbsCertificate,
        signatureAlgorithm: cert.signatureAlgorithm,
        signatureValue: cert.signatureValue,
        issuer: cert.issuer,
        subject: cert.subject,
        notBefore: cert.notBefore,
        notAfter: cert.notAfter,
        subjectPublicKeyInfo: cert.subjectPublicKeyInfo,
        extensions: {
          '1.3.6.1.4.1.53594.1.1': [0xFF, 0xFF],
        },
      );
      expect(parseLibp2pExtension(certWithBadExt), isNull);
    });
  });
}

List<int> _buildTbsWithoutExtensions() {
  final content = <int>[
    0x02, 0x01, 0x01, // SerialNumber
    ..._buildSimpleSigAlg(),
    ...[0x30, 0x00], // empty issuer
    ..._buildValidity(),
    ...[0x30, 0x00], // empty subject
    ...[0x30, 0x00], // empty SPKI
  ];
  return [0x30, content.length, ...content];
}

List<int> _buildTbsWithInvalidTime() {
  // Invalid UTCTime: '01A000000000Z' has a non-digit in the month field.
  final notBefore = _buildUtcTime('01A000000000Z');
  final notAfter = _buildUtcTime('300101000000Z');
  final validity = [
    0x30,
    notBefore.length + notAfter.length,
    ...notBefore,
    ...notAfter
  ];
  final content = <int>[
    0x02, 0x01, 0x01, // SerialNumber
    ..._buildSimpleSigAlg(),
    ...[0x30, 0x00], // empty issuer
    ...validity,
    ...[0x30, 0x00], // empty subject
    ...[0x30, 0x00], // empty SPKI
  ];
  return [0x30, content.length, ...content];
}

List<int> _buildSimpleSigAlg() {
  const content = <int>[0x06, 0x03, 0x2B, 0x65, 0x70, 0x05, 0x00];
  return [
    0x30,
    content.length,
    ...content,
  ];
}

List<int> _buildValidity() {
  final notBefore = _buildUtcTime('010101000000Z');
  final notAfter = _buildUtcTime('300101000000Z');
  final content = [...notBefore, ...notAfter];
  return [0x30, content.length, ...content];
}

List<int> _buildUtcTime(String value) {
  final bytes = value.codeUnits;
  return [0x17, bytes.length, ...bytes];
}

List<int> _buildBitString(List<int> data) {
  final content = [0x00, ...data];
  return [0x03, content.length, ...content];
}

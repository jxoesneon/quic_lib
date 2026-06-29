import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:quic_lib/src/crypto/tls/revocation_parser.dart';
import 'package:test/test.dart';

Uint8List _buildAiaExtensionValue(String ocspUrl) {
  final ocspOid =
      ASN1ObjectIdentifier.fromComponents([1, 3, 6, 1, 5, 5, 7, 48, 1]);
  final uriBytes = ascii.encode(ocspUrl);
  // GeneralName [6] IMPLICIT IA5String: the value is the raw URI bytes.
  final generalName = ASN1Object.fromBytes(Uint8List.fromList([
    0x86,
    uriBytes.length,
    ...uriBytes,
  ]));
  final accessDescription = ASN1Sequence();
  accessDescription.add(ocspOid);
  accessDescription.add(generalName);
  final seq = ASN1Sequence();
  seq.add(accessDescription);
  return seq.encodedBytes;
}

Uint8List _buildCrlDpExtensionValue(String crlUrl) {
  final uriBytes = ascii.encode(crlUrl);
  final generalName = ASN1Object.fromBytes(Uint8List.fromList([
    0x86,
    uriBytes.length,
    ...uriBytes,
  ]));
  final fullName = ASN1Sequence();
  fullName.add(generalName);
  // DistributionPointName [0] EXPLICIT
  final dpName = ASN1Object.fromBytes(Uint8List.fromList([
    0xA0,
    fullName.encodedBytes.length,
    ...fullName.encodedBytes,
  ]));
  final distributionPoint = ASN1Sequence();
  distributionPoint.add(dpName);
  final seq = ASN1Sequence();
  seq.add(distributionPoint);
  return seq.encodedBytes;
}

void main() {
  group('extractRevocationInfo', () {
    test('extracts OCSP URL from Authority Information Access', () {
      final url = 'http://ocsp.example.com/responder';
      final extensions = {
        '1.3.6.1.5.5.7.1.1': _buildAiaExtensionValue(url),
      };
      final info = extractRevocationInfo(extensions);
      expect(info.ocspUrls, hasLength(1));
      expect(info.ocspUrls.first.toString(), equals(url));
      expect(info.crlUrls, isEmpty);
    });

    test('extracts CRL URL from CRLDistributionPoints', () {
      final url = 'http://crl.example.com/root.crl';
      final extensions = {
        '2.5.29.31': _buildCrlDpExtensionValue(url),
      };
      final info = extractRevocationInfo(extensions);
      expect(info.crlUrls, hasLength(1));
      expect(info.crlUrls.first.toString(), equals(url));
      expect(info.ocspUrls, isEmpty);
    });

    test('extracts both OCSP and CRL URLs', () {
      final ocspUrl = 'http://ocsp.example.com/responder';
      final crlUrl = 'http://crl.example.com/root.crl';
      final extensions = {
        '1.3.6.1.5.5.7.1.1': _buildAiaExtensionValue(ocspUrl),
        '2.5.29.31': _buildCrlDpExtensionValue(crlUrl),
      };
      final info = extractRevocationInfo(extensions);
      expect(info.ocspUrls, hasLength(1));
      expect(info.crlUrls, hasLength(1));
      expect(info.ocspUrls.first.toString(), equals(ocspUrl));
      expect(info.crlUrls.first.toString(), equals(crlUrl));
    });

    test('ignores non-OCSP access methods', () {
      final caIssuersOid =
          ASN1ObjectIdentifier.fromComponents([1, 3, 6, 1, 5, 5, 7, 48, 2]);
      final uriBytes = ascii.encode('http://ca.example.com/issuer.crt');
      final generalName = ASN1Object.fromBytes(Uint8List.fromList([
        0x86,
        uriBytes.length,
        ...uriBytes,
      ]));
      final accessDescription = ASN1Sequence();
      accessDescription.add(caIssuersOid);
      accessDescription.add(generalName);
      final valueSeq = ASN1Sequence();
      valueSeq.add(accessDescription);
      final info =
          extractRevocationInfo({'1.3.6.1.5.5.7.1.1': valueSeq.encodedBytes});
      expect(info.ocspUrls, isEmpty);
      expect(info.crlUrls, isEmpty);
    });

    test('returns empty info for empty extensions', () {
      final info = extractRevocationInfo({});
      expect(info.isEmpty, isTrue);
    });

    test('ignores malformed extension bytes', () {
      final info = extractRevocationInfo({
        '1.3.6.1.5.5.7.1.1': [0xFF, 0xFF],
        '2.5.29.31': [0xFF, 0xFF],
      });
      expect(info.isEmpty, isTrue);
    });
  });
}

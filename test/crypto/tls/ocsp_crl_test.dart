import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:quic_lib/src/crypto/tls/crl_fetcher.dart';
import 'package:quic_lib/src/crypto/tls/ocsp_fetcher.dart';
import 'package:test/test.dart';

// ---------------------------------------------------------------------------
// OCSP DER fixture builders
// ---------------------------------------------------------------------------

/// OID for id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1).
final _ocspBasicOid =
    ASN1ObjectIdentifier.fromComponents([1, 3, 6, 1, 5, 5, 7, 48, 1, 1]);

/// Encodes a DER length octet sequence.
Uint8List _encodeLength(int length) {
  if (length <= 127) {
    return Uint8List.fromList([length]);
  }
  final bytes = <int>[];
  var v = length;
  while (v > 0) {
    bytes.insert(0, v & 0xFF);
    v >>= 8;
  }
  return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
}

/// Builds a context-tagged object with [tag] wrapping [content] using proper
/// DER length encoding (handles content longer than 127 bytes).
Uint8List _contextTagged(int tag, List<int> content) {
  final len = _encodeLength(content.length);
  return Uint8List.fromList([tag, ...len, ...content]);
}

/// Builds a CertID SEQUENCE with placeholder hashes and the given serial.
Uint8List _buildCertId(Uint8List serial) {
  final algId = ASN1Sequence();
  algId.add(ASN1ObjectIdentifier.fromComponents([1, 3, 14, 3, 2, 26]));
  algId.add(ASN1Null());

  final certId = ASN1Sequence();
  certId.add(algId);
  certId.add(ASN1OctetString(Uint8List(20))); // issuerNameHash
  certId.add(ASN1OctetString(Uint8List(20))); // issuerKeyHash
  // Decode the raw serial bytes into a BigInt so ASN1Integer encodes correctly.
  certId.add(ASN1Integer(_bytesToBigInt(serial)));
  return certId.encodedBytes;
}

/// Builds a SingleResponse with the given certStatus tag.
///
/// [certStatusTag] is the raw context tag byte:
/// - 0x80 for `good` ([0] IMPLICIT NULL)
/// - 0xA1 for `revoked` ([1] IMPLICIT RevokedInfo)
/// - 0x82 for `unknown` ([2] IMPLICIT UnknownInfo)
Uint8List _buildSingleResponse(int certStatusTag, Uint8List serial) {
  final certId = ASN1Object.fromBytes(_buildCertId(serial));

  // thisUpdate / nextUpdate GeneralizedTime values.
  final thisUpdate = ASN1GeneralizedTime(DateTime.utc(2026, 7, 7, 12, 0, 0));
  final nextUpdate = ASN1GeneralizedTime(DateTime.utc(2026, 7, 14, 12, 0, 0));

  // certStatus as a context-tagged object.
  final Uint8List certStatusBytes;
  if (certStatusTag == 0xA1) {
    // RevokedInfo ::= SEQUENCE { revocationDate GeneralizedTime,
    //   revocationReason [0] EXPLICIT OPTIONAL }
    final revokedInfo = ASN1Sequence();
    revokedInfo.add(ASN1GeneralizedTime(DateTime.utc(2026, 6, 1, 0, 0, 0)));
    certStatusBytes = _contextTagged(0xA1, revokedInfo.encodedBytes);
  } else {
    certStatusBytes = Uint8List.fromList([certStatusTag, 0x00]);
  }
  final certStatus = ASN1Object.fromBytes(certStatusBytes);

  // nextUpdate is [0] EXPLICIT GeneralizedTime.
  final nextUpdateWrapped =
      ASN1Object.fromBytes(_contextTagged(0xA0, nextUpdate.encodedBytes));

  final singleResponse = ASN1Sequence();
  singleResponse.add(certId);
  singleResponse.add(certStatus);
  singleResponse.add(thisUpdate);
  singleResponse.add(nextUpdateWrapped);
  return singleResponse.encodedBytes;
}

/// Builds a complete OCSPResponse DER with the given SingleResponse certStatus
/// tag.
Uint8List _buildOcspResponse(int certStatusTag, {Uint8List? serial}) {
  final serialArg = serial ?? Uint8List.fromList([0x01, 0x02, 0x03]);
  final singleResponse = _buildSingleResponse(certStatusTag, serialArg);

  // responses ::= SEQUENCE OF SingleResponse
  final responses = ASN1Sequence();
  responses.add(ASN1Object.fromBytes(singleResponse));

  // responderID byName [0] EXPLICIT UTF8String (minimal).
  final responderId = ASN1Object.fromBytes(
    _contextTagged(0xA0, (ASN1UTF8String('CN=OCSP Responder')).encodedBytes),
  );
  final producedAt = ASN1GeneralizedTime(DateTime.utc(2026, 7, 7, 12, 30, 0));

  // ResponseData ::= SEQUENCE { responderID, producedAt, responses }
  final responseData = ASN1Sequence();
  responseData.add(responderId);
  responseData.add(producedAt);
  responseData.add(responses);

  // BasicOCSPResponse ::= SEQUENCE { responseData, signatureAlgorithm,
  //                                  signature BIT STRING }
  final sigAlg = ASN1Sequence();
  sigAlg.add(ASN1ObjectIdentifier.fromComponents([1, 3, 14, 3, 2, 26]));
  sigAlg.add(ASN1Null());
  final signature = ASN1BitString(Uint8List(8));
  final basicResponse = ASN1Sequence();
  basicResponse.add(responseData);
  basicResponse.add(sigAlg);
  basicResponse.add(signature);

  // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
  final responseBytes = ASN1Sequence();
  responseBytes.add(_ocspBasicOid);
  responseBytes.add(ASN1OctetString(basicResponse.encodedBytes));

  // responseBytes [0] EXPLICIT
  final responseBytesTagged =
      ASN1Object.fromBytes(_contextTagged(0xA0, responseBytes.encodedBytes));

  // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes }
  final ocspResponse = ASN1Sequence();
  ocspResponse.add(ASN1Integer(BigInt.zero)); // status successful (0)
  ocspResponse.add(responseBytesTagged);
  return ocspResponse.encodedBytes;
}

/// Builds an OCSPResponse whose top-level status is non-successful.
Uint8List _buildOcspFailureResponse(int status) {
  final ocspResponse = ASN1Sequence();
  ocspResponse.add(ASN1Integer(BigInt.from(status)));
  return ocspResponse.encodedBytes;
}

// ---------------------------------------------------------------------------
// CRL DER fixture builders
// ---------------------------------------------------------------------------

/// Builds a minimal CRL whose revokedCertificates list contains [serials].
Uint8List _buildCrl(List<Uint8List> serials) {
  // signature AlgorithmIdentifier
  final sigAlg = ASN1Sequence();
  sigAlg.add(ASN1ObjectIdentifier.fromComponents([1, 3, 14, 3, 2, 26]));
  sigAlg.add(ASN1Null());

  // issuer Name ::= SEQUENCE OF SET OF AttributeTypeAndValue
  final rdn = ASN1Set();
  rdn.add(ASN1UTF8String('CN=Test Issuer'));
  final issuer = ASN1Sequence();
  issuer.add(rdn);

  final thisUpdate = ASN1UtcTime(DateTime.utc(2026, 7, 7, 12, 0, 0));

  // revokedCertificates ::= SEQUENCE OF SEQUENCE { serial, revocationDate }
  final revokedList = ASN1Sequence();
  for (final serial in serials) {
    final entry = ASN1Sequence();
    entry.add(ASN1Integer(_bytesToBigInt(serial)));
    entry.add(ASN1UtcTime(DateTime.utc(2026, 6, 1, 0, 0, 0)));
    revokedList.add(entry);
  }

  // TBSCertList ::= SEQUENCE { version, signature, issuer, thisUpdate,
  //   revokedCertificates }
  final tbs = ASN1Sequence();
  tbs.add(ASN1Integer(BigInt.one)); // version v2
  tbs.add(sigAlg);
  tbs.add(issuer);
  tbs.add(thisUpdate);
  if (serials.isNotEmpty) {
    tbs.add(revokedList);
  }

  // CertificateList ::= SEQUENCE { tbs, signatureAlgorithm, signatureValue }
  final crl = ASN1Sequence();
  crl.add(tbs);
  crl.add(sigAlg);
  crl.add(ASN1BitString(Uint8List(8)));
  return crl.encodedBytes;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  group('OcspFetcher.parseResponse', () {
    late OcspFetcher fetcher;

    setUp(() => fetcher = OcspFetcher());
    tearDown(() => fetcher.close());

    test('parses a `good` verdict', () {
      final der = _buildOcspResponse(0x80);
      final verdict = fetcher.parseResponse(Uint8List.fromList(der));
      expect(verdict.status, equals(OcspCertStatus.good));
      expect(verdict.thisUpdate, isNotNull);
      expect(verdict.nextUpdate, isNotNull);
    });

    test('parses a `revoked` verdict', () {
      final der = _buildOcspResponse(0xA1);
      final verdict = fetcher.parseResponse(Uint8List.fromList(der));
      expect(verdict.status, equals(OcspCertStatus.revoked));
    });

    test('parses an `unknown` certStatus', () {
      final der = _buildOcspResponse(0x82);
      final verdict = fetcher.parseResponse(Uint8List.fromList(der));
      expect(verdict.status, equals(OcspCertStatus.unknown));
    });

    test('returns unknown for non-successful response status', () {
      // 1 = malformedRequest
      final der = _buildOcspFailureResponse(1);
      final verdict = fetcher.parseResponse(Uint8List.fromList(der));
      expect(verdict.status, equals(OcspCertStatus.unknown));
    });

    test('throws OcspException for invalid DER', () {
      expect(
        () => fetcher.parseResponse(Uint8List.fromList([0xFF, 0xFF])),
        throwsA(isA<OcspException>()),
      );
    });
  });

  group('buildOcspRequest', () {
    test('produces a DER-encoded OCSPRequest SEQUENCE', () {
      final request = buildOcspRequest(
        issuerNameHash: Uint8List(20),
        issuerKeyHash: Uint8List(20),
        serialNumber: Uint8List.fromList([0x7F, 0x01]),
      );
      expect(request.first, equals(0x30)); // SEQUENCE tag
      // Re-parse to confirm structure.
      final parser = ASN1Parser(request);
      final ocspRequest = parser.nextObject() as ASN1Sequence;
      expect(ocspRequest.elements.length, greaterThanOrEqualTo(1));
    });
  });

  group('CrlFetcher.isRevoked', () {
    late CrlFetcher fetcher;

    setUp(() => fetcher = CrlFetcher());
    tearDown(() => fetcher.close());

    test('returns true when the serial is in the revoked list', () {
      final serial = Uint8List.fromList([0x01, 0x02, 0x03]);
      final crl = _buildCrl([
        Uint8List.fromList([0x04, 0x05]),
        serial,
      ]);
      expect(fetcher.isRevoked(Uint8List.fromList(crl), serial), isTrue);
    });

    test('returns false when the serial is not in the revoked list', () {
      final serial = Uint8List.fromList([0x01, 0x02, 0x03]);
      final crl = _buildCrl([
        Uint8List.fromList([0x04, 0x05]),
        Uint8List.fromList([0x06, 0x07]),
      ]);
      expect(fetcher.isRevoked(Uint8List.fromList(crl), serial), isFalse);
    });

    test('returns false when the CRL has no revokedCertificates', () {
      final serial = Uint8List.fromList([0x01, 0x02, 0x03]);
      final crl = _buildCrl([]);
      expect(fetcher.isRevoked(Uint8List.fromList(crl), serial), isFalse);
    });

    test('tolerates leading-zero padding differences', () {
      final serial = Uint8List.fromList([0x01, 0x02]);
      final crl = _buildCrl([
        Uint8List.fromList([0x00, 0x01, 0x02]),
      ]);
      expect(fetcher.isRevoked(Uint8List.fromList(crl), serial), isTrue);
    });

    test('throws CrlException for invalid DER', () {
      expect(
        () => fetcher.isRevoked(
          Uint8List.fromList([0xFF, 0xFF]),
          Uint8List.fromList([0x01]),
        ),
        throwsA(isA<CrlException>()),
      );
    });
  });
}

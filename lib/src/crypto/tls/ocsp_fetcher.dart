import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart' as pc;

/// The revocation status of a certificate as reported by an OCSP responder.
enum OcspCertStatus {
  /// The certificate is not revoked (`certStatus` choice `[0] good`).
  good,

  /// The certificate has been revoked (`certStatus` choice `[1] revoked`).
  revoked,

  /// The responder has no information about the certificate
  /// (`certStatus` choice `[2] unknown`).
  unknown,
}

/// The verdict returned by [OcspFetcher] after querying an OCSP responder.
///
/// Contains the parsed [status] plus the `thisUpdate` / `nextUpdate` freshness
/// timestamps from the [SingleResponse](https://datatracker.ietf.org/doc/html/rfc6960#section-4.2.1).
class OcspVerdict {
  /// The revocation status reported by the responder.
  final OcspCertStatus status;

  /// The time at which the status was asserted to be correct (`thisUpdate`).
  ///
  /// `null` when the responder did not include the field or the response was
  /// not a successful `BasicOCSPResponse`.
  final DateTime? thisUpdate;

  /// The time at which the status assertion expires (`nextUpdate`).
  ///
  /// `null` when the responder did not include the field.
  final DateTime? nextUpdate;

  /// Creates an OCSP verdict.
  const OcspVerdict({
    required this.status,
    this.thisUpdate,
    this.nextUpdate,
  });

  @override
  String toString() => 'OcspVerdict(status: $status, thisUpdate: $thisUpdate, '
      'nextUpdate: $nextUpdate)';
}

/// OCSP response status values per RFC 6960 Section 4.2.1.
const _ocspResponseStatusSuccessful = 0;

/// OID for `id-pkix-ocsp-basic` (1.3.6.1.5.5.7.48.1.1).
const _idPkixOcspBasicDotted = '1.3.6.1.5.5.7.48.1.1';

/// OID for the SHA-1 algorithm identifier used in the default OCSP `CertID`.
final _sha1AlgorithmIdentifier = _buildSha1AlgorithmIdentifier();

ASN1Sequence _buildSha1AlgorithmIdentifier() {
  // AlgorithmIdentifier ::= SEQUENCE { OID, parameters NULL }
  // SHA-1 OID: 1.3.14.3.2.26
  final seq = ASN1Sequence();
  seq.add(ASN1ObjectIdentifier.fromComponents([1, 3, 14, 3, 2, 26]));
  seq.add(ASN1Null());
  return seq;
}

/// Fetches and parses OCSP responses (RFC 6960).
///
/// [OcspFetcher] performs an HTTP POST of a DER-encoded `OCSPRequest` to an
/// OCSP responder URL (typically obtained from
/// [RevocationInfo.ocspUrls]), then parses the returned DER-encoded
/// `OCSPResponse` and returns an [OcspVerdict].
///
/// The network [fetch] method is separated from [parseResponse] so that the
/// parsing logic can be unit-tested with static DER fixtures without requiring
/// a live responder.
///
/// ## Example
/// ```dart
/// final fetcher = OcspFetcher();
/// final request = buildOcspRequest(
///   issuerNameHash: nameHash,
///   issuerKeyHash: keyHash,
///   serialNumber: serial,
/// );
/// final verdict = await fetcher.fetch(ocspUrl, request);
/// if (verdict.status == OcspCertStatus.revoked) {
///   // reject the certificate
/// }
/// ```
class OcspFetcher {
  /// HTTP client used for responder requests.
  ///
  /// Exposed so callers can configure timeouts, proxy settings, or inject a
  /// mock for testing.
  final HttpClient httpClient;

  /// Creates an [OcspFetcher] with an optional [httpClient].
  ///
  /// If [httpClient] is omitted a default [HttpClient] is created and will be
  /// closed by [close].
  OcspFetcher({HttpClient? httpClient})
      : httpClient = httpClient ?? HttpClient();

  /// Closes the underlying [HttpClient] if it was created internally.
  ///
  /// Callers that supplied their own [HttpClient] are responsible for closing
  /// it themselves; calling [close] in that case is a no-op only if a custom
  /// client was passed and `ownClient` was false. For simplicity this method
  /// always closes [httpClient].
  void close() {
    httpClient.close();
  }

  /// POSTs a DER-encoded [ocspRequest] to the OCSP responder at [url] and
  /// returns the parsed [OcspVerdict].
  ///
  /// The request is sent with `Content-Type: application/ocsp-request` per
  /// RFC 6960 Section A.1.1. The response is expected to be a DER-encoded
  /// `OCSPResponse` (`application/ocsp-response`).
  ///
  /// Throws [OcspException] if the HTTP request fails or the response cannot
  /// be parsed.
  Future<OcspVerdict> fetch(Uri url, Uint8List ocspRequest) async {
    final request = await httpClient.postUrl(url);
    request.headers.contentType = ContentType.parse('application/ocsp-request');
    request.add(ocspRequest);
    final response = await request.close();

    final body = <int>[];
    await for (final chunk in response) {
      body.addAll(chunk);
    }

    if (response.statusCode != HttpStatus.ok) {
      throw OcspException(
        'OCSP responder returned HTTP ${response.statusCode}',
      );
    }

    return parseResponse(Uint8List.fromList(body));
  }

  /// Parses a DER-encoded `OCSPResponse` ([der]) and returns the
  /// [OcspVerdict] for the first [SingleResponse] contained in the
  /// `BasicOCSPResponse`.
  ///
  /// If the top-level `responseStatus` is not `successful` (0), an
  /// [OcspVerdict] with [OcspCertStatus.unknown] is returned. If the response
  /// carries no `responseBytes` or a non-basic response type, the verdict is
  /// also [OcspCertStatus.unknown].
  ///
  /// Throws [OcspException] if [der] is not valid DER.
  OcspVerdict parseResponse(Uint8List der) {
    final parser = ASN1Parser(der);
    final ASN1Sequence response;
    try {
      response = parser.nextObject() as ASN1Sequence;
    } catch (e) {
      throw OcspException('Invalid OCSPResponse DER: $e');
    }

    if (response.elements.isEmpty) {
      throw OcspException('Empty OCSPResponse');
    }

    final statusElement = response.elements.first;
    // ENUMERATED is parsed as ASN1Integer by asn1lib.
    if (statusElement is! ASN1Integer) {
      throw OcspException('Missing OCSPResponseStatus');
    }
    final statusValue = statusElement.valueAsBigInteger.toInt();
    if (statusValue != _ocspResponseStatusSuccessful) {
      // Non-successful response — there is no cert status to report.
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }

    if (response.elements.length < 2) {
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }

    // responseBytes [0] EXPLICIT { SEQUENCE { OID, OCTET STRING } }
    final responseBytesTagged = response.elements[1];
    final rbParser = ASN1Parser(responseBytesTagged.valueBytes());
    final responseBytes = rbParser.nextObject() as ASN1Sequence;
    if (responseBytes.elements.length < 2) {
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }

    final responseType = responseBytes.elements.first as ASN1ObjectIdentifier;
    if (responseType.identifier != _idPkixOcspBasicDotted) {
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }

    final basicResponseDer =
        (responseBytes.elements[1] as ASN1OctetString).valueBytes();
    return _parseBasicOcspResponse(Uint8List.fromList(basicResponseDer));
  }

  OcspVerdict _parseBasicOcspResponse(Uint8List der) {
    final parser = ASN1Parser(der);
    final basicResponse = parser.nextObject() as ASN1Sequence;
    if (basicResponse.elements.isEmpty) {
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }
    // ResponseData is the first element.
    final responseData = basicResponse.elements.first as ASN1Sequence;
    return _parseResponseData(responseData);
  }

  OcspVerdict _parseResponseData(ASN1Sequence responseData) {
    // ResponseData ::= SEQUENCE {
    //   version [0] OPTIONAL,
    //   responderID (CHOICE [0]/[1]),
    //   producedAt GeneralizedTime,
    //   responses SEQUENCE OF SingleResponse,
    //   responseExtensions [1] OPTIONAL }
    //
    // The responderID is a CHOICE encoded with context tags, so we locate the
    // SEQUENCE OF SingleResponse by scanning for the first constructed
    // SEQUENCE whose first child is itself a SEQUENCE (CertID).
    ASN1Sequence? responses;
    for (final element in responseData.elements) {
      if (element is ASN1Sequence) {
        // A SingleResponse is a SEQUENCE whose first child is a CertID
        // SEQUENCE. The `responses` wrapper is a SEQUENCE OF SingleResponse.
        // Distinguish the wrapper from responderID/producedAt by checking
        // that its first child is a SEQUENCE (CertID).
        if (element.elements.isNotEmpty &&
            element.elements.first is ASN1Sequence) {
          responses = element;
          break;
        }
      }
    }

    if (responses == null || responses.elements.isEmpty) {
      return const OcspVerdict(status: OcspCertStatus.unknown);
    }

    final singleResponse = responses.elements.first as ASN1Sequence;
    return _parseSingleResponse(singleResponse);
  }

  OcspVerdict _parseSingleResponse(ASN1Sequence singleResponse) {
    // SingleResponse ::= SEQUENCE {
    //   certID CertID,
    //   certStatus CertStatus,
    //   thisUpdate GeneralizedTime,
    //   nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
    //   singleExtensions [1] EXPLICIT Extensions OPTIONAL }
    //
    // certStatus is a CHOICE:
    //   good    [0] IMPLICIT NULL        -> tag 0x80
    //   revoked [1] IMPLICIT RevokedInfo -> tag 0xA1 (constructed)
    //   unknown [2] IMPLICIT UnknownInfo -> tag 0x82
    OcspCertStatus status = OcspCertStatus.unknown;
    DateTime? thisUpdate;
    DateTime? nextUpdate;

    for (final element in singleResponse.elements) {
      final tag = element.tag;
      if (tag == 0x80) {
        status = OcspCertStatus.good;
      } else if (tag == 0xA1 || tag == 0x81) {
        status = OcspCertStatus.revoked;
      } else if (tag == 0x82) {
        status = OcspCertStatus.unknown;
      } else if (element is ASN1GeneralizedTime) {
        if (thisUpdate == null) {
          thisUpdate = element.dateTimeValue;
        } else {
          nextUpdate ??= element.dateTimeValue;
        }
      } else if ((tag & 0xA0) == 0xA0 && nextUpdate == null) {
        // [0] EXPLICIT nextUpdate wrapper.
        final innerParser = ASN1Parser(element.valueBytes());
        final inner = innerParser.nextObject();
        if (inner is ASN1GeneralizedTime) {
          nextUpdate = inner.dateTimeValue;
        }
      }
    }

    return OcspVerdict(
      status: status,
      thisUpdate: thisUpdate,
      nextUpdate: nextUpdate,
    );
  }
}

/// Builds a minimal DER-encoded `OCSPRequest` (RFC 6960 Section 4.1.1).
///
/// The request contains a single [Request](certID) using the supplied
/// [issuerNameHash], [issuerKeyHash], and [serialNumber]. The default hash
/// algorithm is SHA-1, matching the most widely deployed OCSP responders.
///
/// [issuerNameHash] is the hash of the issuer's DER-encoded Name.
/// [issuerKeyHash] is the hash of the issuer's subject public key BIT STRING
/// value (excluding tag, length, and the unused-bits octet).
/// [serialNumber] is the raw INTEGER value bytes of the target certificate's
/// serial number.
///
/// Pass [hashAlgorithm] to use a non-default AlgorithmIdentifier SEQUENCE.
Uint8List buildOcspRequest({
  required Uint8List issuerNameHash,
  required Uint8List issuerKeyHash,
  required Uint8List serialNumber,
  ASN1Sequence? hashAlgorithm,
}) {
  final algId = hashAlgorithm ?? _sha1AlgorithmIdentifier;

  // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash,
  //                       serialNumber INTEGER }
  final certId = ASN1Sequence();
  certId.add(algId);
  certId.add(ASN1OctetString(issuerNameHash));
  certId.add(ASN1OctetString(issuerKeyHash));
  certId.add(ASN1Integer(_bytesToBigInt(serialNumber)));

  // Request ::= SEQUENCE { reqCert CertID }
  final request = ASN1Sequence();
  request.add(certId);

  // TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
  final requestList = ASN1Sequence();
  requestList.add(request);

  final tbsRequest = ASN1Sequence();
  tbsRequest.add(requestList);

  // OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature OPTIONAL }
  final ocspRequest = ASN1Sequence();
  ocspRequest.add(tbsRequest);

  return ocspRequest.encodedBytes;
}

/// Computes the SHA-1 digest of [data] using pointycastle.
Uint8List sha1Digest(Uint8List data) {
  final digest = pc.SHA1Digest();
  return digest.process(data);
}

/// Converts a big-endian unsigned byte sequence to a [BigInt].
BigInt _bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// Exception thrown when an OCSP fetch or parse operation fails.
class OcspException implements Exception {
  /// Human-readable description of the failure.
  final String message;

  /// Creates an [OcspException] with [message].
  OcspException(this.message);

  @override
  String toString() => 'OcspException: $message';
}

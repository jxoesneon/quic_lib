import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';

/// Fetches and parses X.509 Certificate Revocation Lists (CRLs) per
/// RFC 5280 Section 5.
///
/// [CrlFetcher] performs an HTTP GET of a DER-encoded CRL from a distribution
/// point URL (typically obtained from [RevocationInfo.crlUrls]), parses the
/// `revokedCertificates` list, and reports whether a given certificate serial
/// number is present.
///
/// The network [fetch] method is separated from [isRevoked] so that the
/// parsing logic can be unit-tested with static DER fixtures without requiring
/// a live CRL distribution point.
///
/// ## Example
/// ```dart
/// final fetcher = CrlFetcher();
/// final revoked = await fetcher.fetch(crlUrl, cert.serialNumber);
/// if (revoked) {
///   // reject the certificate
/// }
/// ```
class CrlFetcher {
  /// HTTP client used for CRL distribution-point requests.
  ///
  /// Exposed so callers can configure timeouts, proxy settings, or inject a
  /// mock for testing.
  final HttpClient httpClient;

  /// Creates a [CrlFetcher] with an optional [httpClient].
  ///
  /// If [httpClient] is omitted a default [HttpClient] is created.
  CrlFetcher({HttpClient? httpClient})
      : httpClient = httpClient ?? HttpClient();

  /// Closes the underlying [HttpClient].
  void close() {
    httpClient.close();
  }

  /// GETs a DER-encoded CRL from [url] and returns `true` if the certificate
  /// identified by [serialNumber] is listed as revoked.
  ///
  /// [serialNumber] is the raw DER INTEGER value bytes of the target
  /// certificate's serial number (as exposed by
  /// [X509Certificate.serialNumber]).
  ///
  /// The request is sent with `Accept: application/pkix-crl` per
  /// RFC 5280. The response is expected to be DER-encoded.
  ///
  /// Throws [CrlException] if the HTTP request fails or the CRL cannot be
  /// parsed. Returns `false` if the CRL contains no `revokedCertificates`
  /// list (i.e. no certificates have been revoked).
  Future<bool> fetch(Uri url, List<int> serialNumber) async {
    final request = await httpClient.getUrl(url);
    request.headers.set('Accept', 'application/pkix-crl');
    final response = await request.close();

    final body = <int>[];
    await for (final chunk in response) {
      body.addAll(chunk);
    }

    if (response.statusCode != HttpStatus.ok) {
      throw CrlException(
        'CRL distribution point returned HTTP ${response.statusCode}',
      );
    }

    return isRevoked(Uint8List.fromList(body), serialNumber);
  }

  /// Parses a DER-encoded CRL ([crlDer]) and returns `true` if
  /// [serialNumber] appears in the `revokedCertificates` list.
  ///
  /// [serialNumber] is compared as a big-endian unsigned integer against each
  /// `userCertificate` serial in the CRL. Leading zero padding differences are
  /// tolerated.
  ///
  /// Throws [CrlException] if [crlDer] is not a valid DER-encoded CRL.
  bool isRevoked(Uint8List crlDer, List<int> serialNumber) {
    final ASN1Sequence crl;
    try {
      final parser = ASN1Parser(crlDer);
      crl = parser.nextObject() as ASN1Sequence;
    } catch (e) {
      throw CrlException('Invalid CRL DER: $e');
    }

    if (crl.elements.isEmpty) {
      throw CrlException('Empty CRL');
    }

    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
    //                                signatureValue }
    final tbsCertList = crl.elements.first as ASN1Sequence;
    return _isRevokedInTbs(tbsCertList, serialNumber);
  }

  bool _isRevokedInTbs(ASN1Sequence tbsCertList, List<int> serialNumber) {
    // TBSCertList ::= SEQUENCE {
    //   version                 Version OPTIONAL,
    //   signature               AlgorithmIdentifier,
    //   issuer                  Name,
    //   thisUpdate              Time,
    //   nextUpdate              Time OPTIONAL,
    //   revokedCertificates     SEQUENCE OF SEQUENCE {
    //       userCertificate         CertificateSerialNumber,
    //       revocationDate          Time,
    //       crlEntryExtensions      Extensions OPTIONAL
    //   } OPTIONAL,
    //   crlExtensions            [0] EXPLICIT Extensions OPTIONAL
    // }
    //
    // We scan for the revokedCertificates SEQUENCE OF SEQUENCE. It is the only
    // direct child of tbsCertList that is a SEQUENCE whose first child is also
    // a SEQUENCE: the issuer Name is a SEQUENCE OF SET, the signature
    // AlgorithmIdentifier's first child is an OID, and the Time fields are not
    // SEQUENCEs.
    for (final element in tbsCertList.elements) {
      if (element is ASN1Sequence &&
          element.elements.isNotEmpty &&
          element.elements.first is ASN1Sequence) {
        return _serialInRevokedList(element, serialNumber);
      }
    }
    return false;
  }

  bool _serialInRevokedList(ASN1Sequence revokedList, List<int> serialNumber) {
    final target = _normalizeSerial(serialNumber);
    for (final entryObj in revokedList.elements) {
      final entry = entryObj as ASN1Sequence;
      if (entry.elements.isEmpty) continue;
      final serial = entry.elements.first as ASN1Integer;
      if (_normalizeSerial(serial.valueBytes()) == target) {
        return true;
      }
    }
    return false;
  }

  /// Normalizes a serial number by stripping leading zero bytes so that
  /// representations with different sign-padding compare equal.
  String _normalizeSerial(List<int> bytes) {
    var start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    return bytes
        .sublist(start)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
  }
}

/// Exception thrown when a CRL fetch or parse operation fails.
class CrlException implements Exception {
  /// Human-readable description of the failure.
  final String message;

  /// Creates a [CrlException] with [message].
  CrlException(this.message);

  @override
  String toString() => 'CrlException: $message';
}

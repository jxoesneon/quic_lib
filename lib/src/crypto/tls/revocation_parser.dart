import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:x509/x509.dart' as x509;

/// Parsed revocation pointers extracted from a certificate's X.509 extensions.
///
/// This value object contains HTTP/HTTPS OCSP responder URLs and CRL
/// distribution point URLs. The actual fetching and verification of CRLs
/// or OCSP responses is not performed by this class; it is the Phase 1
/// foundation for future revocation checking.
class RevocationInfo {
  /// OCSP responder URLs parsed from the Authority Information Access (AIA)
  /// extension (OID 1.3.6.1.5.5.7.1.1) with access method `id-ad-ocsp`.
  final List<Uri> ocspUrls;

  /// CRL distribution point URLs parsed from the CRLDistributionPoints
  /// extension (OID 2.5.29.31).
  final List<Uri> crlUrls;

  const RevocationInfo({this.ocspUrls = const [], this.crlUrls = const []});

  /// Returns `true` if no revocation pointers were found.
  bool get isEmpty => ocspUrls.isEmpty && crlUrls.isEmpty;

  /// Returns `true` if at least one OCSP or CRL URL was found.
  bool get isNotEmpty => !isEmpty;

  @override
  String toString() =>
      'RevocationInfo(ocsp=${ocspUrls.length}, crl=${crlUrls.length})';
}

const _authorityInfoAccessOid = '1.3.6.1.5.5.7.1.1';
const _crlDistributionPointsOid = '2.5.29.31';
final _idAdOcsp = x509.ObjectIdentifier([1, 3, 6, 1, 5, 5, 7, 48, 1]);

/// Extracts OCSP and CRL distribution URLs from the supplied X.509 extension
/// map.
///
/// [extensions] is the map produced by [parseX509] where keys are dotted OID
/// strings and values are the raw DER extension value bytes. Malformed or
/// unsupported extensions are ignored.
RevocationInfo extractRevocationInfo(Map<String, List<int>> extensions) {
  final ocsp = <Uri>[];
  final crls = <Uri>[];

  final aiaRaw = extensions[_authorityInfoAccessOid];
  if (aiaRaw != null) {
    try {
      final aia = _parseAuthorityInfoAccess(Uint8List.fromList(aiaRaw));
      for (final d in aia.descriptions) {
        if (d.accessMethod == _idAdOcsp && d.accessLocation != null) {
          final uri = Uri.tryParse(d.accessLocation!);
          if (uri != null) {
            ocsp.add(uri);
          }
        }
      }
    } catch (_) {
      // Ignore malformed AIA extension.
    }
  }

  final crlRaw = extensions[_crlDistributionPointsOid];
  if (crlRaw != null) {
    try {
      final crlUrls =
          _extractCrlDistributionPointUrls(Uint8List.fromList(crlRaw));
      crls.addAll(crlUrls);
    } catch (_) {
      // Ignore malformed CRLDistributionPoints extension.
    }
  }

  return RevocationInfo(ocspUrls: ocsp, crlUrls: crls);
}

x509.AuthorityInformationAccess _parseAuthorityInfoAccess(Uint8List bytes) {
  final parser = ASN1Parser(bytes);
  final obj = parser.nextObject();
  final id = x509.ObjectIdentifier([1, 3, 6, 1, 5, 5, 7, 1, 1]);
  return x509.ExtensionValue.fromAsn1(obj, id)
      as x509.AuthorityInformationAccess;
}

/// Manually extracts URI strings from a CRLDistributionPoints extension value.
///
/// We avoid the `x509` package's `CrlDistributionPoints` parser because the
/// version in `package:x509` 0.2.x mishandles the context-specific wrapping of
/// [DistributionPointName]. This parser only looks for the common
/// `fullName [0] SEQUENCE { [6] IA5String uri }` layout.
List<Uri> _extractCrlDistributionPointUrls(Uint8List bytes) {
  final result = <Uri>[];
  final topParser = ASN1Parser(bytes);
  final topSeq = topParser.nextObject() as ASN1Sequence;
  for (final dpObj in topSeq.elements) {
    final dpSeq = dpObj as ASN1Sequence;
    for (final dpElement in dpSeq.elements) {
      if ((dpElement.tag & 0xA0) == 0xA0) {
        // distributionPoint [0] or cRLIssuer [2]
        final innerParser = ASN1Parser(dpElement.valueBytes());
        final innerObj = innerParser.nextObject();
        if (innerObj is ASN1Sequence) {
          for (final gn in innerObj.elements) {
            final uri = _parseUriGeneralName(gn);
            if (uri != null) result.add(uri);
          }
        }
      }
    }
  }
  return result;
}

/// Parses a GeneralName and returns a URI only if the choice is [6] URI.
Uri? _parseUriGeneralName(ASN1Object obj) {
  final tag = obj.tag;
  final choice = tag & 0x1F;
  if (choice != 6) return null;
  try {
    final uriString = String.fromCharCodes(obj.valueBytes());
    return Uri.tryParse(uriString);
  } catch (_) {
    return null;
  }
}

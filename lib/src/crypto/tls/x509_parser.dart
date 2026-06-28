import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/libp2p/libp2p_tls_extension.dart';

/// A parsed X.509 certificate with all essential fields extracted.
///
/// Per RFC 5280, a certificate contains:
///   Certificate  ::=  SEQUENCE  {
///        tbsCertificate       TBSCertificate,
///        signatureAlgorithm     AlgorithmIdentifier,
///        signatureValue         BIT STRING  }
class X509Certificate {
  /// The raw DER-encoded to-be-signed (TBS) portion of the certificate.
  final List<int> tbsCertificate;

  /// Human-readable signature algorithm identifier (e.g. `'ed25519'`,
  /// `'ecdsaP256'`, `'rsaPkcs1Sha256'`).
  final String signatureAlgorithm;

  /// The raw signature value extracted from the certificate.
  final List<int> signatureValue;

  /// DER-encoded Name structure of the issuer.
  final List<int> issuer;

  /// DER-encoded Name structure of the subject.
  final List<int> subject;

  /// Start of the validity period.
  final DateTime notBefore;

  /// End of the validity period.
  final DateTime notAfter;

  /// DER-encoded SubjectPublicKeyInfo structure.
  final List<int> subjectPublicKeyInfo;

  /// Parsed X.509 extensions as a map from OID dotted string to the raw
  /// extension value bytes (the OCTET STRING contents).
  final Map<String, List<int>> extensions;

  X509Certificate({
    required this.tbsCertificate,
    required this.signatureAlgorithm,
    required this.signatureValue,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.subjectPublicKeyInfo,
    this.extensions = const {},
  });
}

// ---------------------------------------------------------------------------
// ASN.1 / DER helpers
// ---------------------------------------------------------------------------

class _Asn1Node {
  final int tag;
  final int start;
  final int length;
  final int valueStart;
  final int valueEnd;

  _Asn1Node({
    required this.tag,
    required this.start,
    required this.length,
    required this.valueStart,
    required this.valueEnd,
  });

  int get end => valueEnd;

  Uint8List rawValue(Uint8List bytes) => bytes.sublist(valueStart, valueEnd);
}

/// Parse the length octets of a DER-encoded ASN.1 element starting at
/// [offset]. Returns `(length, bytesRead)`.
(int, int) _parseDerLength(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw FormatException('Unexpected end of DER data');
  }
  final first = bytes[offset];
  if ((first & 0x80) == 0) {
    // Short form
    return (first & 0x7F, 1);
  }
  final numBytes = first & 0x7F;
  if (numBytes == 0) {
    throw FormatException('Indefinite length not supported');
  }
  if (offset + 1 + numBytes > bytes.length) {
    throw FormatException('DER length exceeds data');
  }
  var length = 0;
  for (var i = 0; i < numBytes; i++) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return (length, 1 + numBytes);
}

/// Parse a single DER node at [offset], returning the node and its end offset.
_Asn1Node _parseDerNode(Uint8List bytes, int offset) {
  if (offset >= bytes.length) {
    throw FormatException('Unexpected end of DER data');
  }
  final tag = bytes[offset];
  final (length, lenBytes) = _parseDerLength(bytes, offset + 1);
  final valueStart = offset + 1 + lenBytes;
  final valueEnd = valueStart + length;
  if (valueEnd > bytes.length) {
    throw FormatException('DER element length exceeds buffer');
  }
  return _Asn1Node(
    tag: tag,
    start: offset,
    length: length,
    valueStart: valueStart,
    valueEnd: valueEnd,
  );
}

/// Parse all immediate child nodes of a constructed DER element.
///
/// If a child cannot be parsed (e.g., invalid tag or length), parsing stops
/// and the children collected so far are returned. This allows graceful
/// handling of partial or synthetic test data.
List<_Asn1Node> _parseChildren(Uint8List bytes, int start, int end) {
  final children = <_Asn1Node>[];
  var offset = start;
  while (offset < end) {
    try {
      final node = _parseDerNode(bytes, offset);
      children.add(node);
      offset = node.end;
    } catch (_) {
      break;
    }
  }
  return children;
}

// ---------------------------------------------------------------------------
// OID -> algorithm name mapping
// ---------------------------------------------------------------------------

String _oidBytesToDotted(List<int> oidBytes) {
  if (oidBytes.isEmpty) return '';
  final parts = <String>[];
  parts.add('${oidBytes[0] ~/ 40}.${oidBytes[0] % 40}');
  var i = 1;
  while (i < oidBytes.length) {
    var value = 0;
    while (true) {
      if (i >= oidBytes.length) return parts.join('.');
      final b = oidBytes[i];
      i++;
      value = (value << 7) | (b & 0x7F);
      if ((b & 0x80) == 0) break;
    }
    parts.add(value.toString());
  }
  return parts.join('.');
}

String _oidToAlgorithm(List<int> oidBytes) {
  final oid = _oidBytesToDotted(oidBytes);

  // Common X.509 signature algorithm OIDs.
  switch (oid) {
    case '1.3.101.112':
      return 'ed25519';
    case '1.2.840.10045.4.3.2':
      return 'ecdsaP256';
    case '1.2.840.113549.1.1.11':
      return 'rsaPkcs1Sha256';
    case '1.2.840.113549.1.1.12':
      return 'rsaPkcs1Sha384';
    default:
      return 'unknown';
  }
}

// ---------------------------------------------------------------------------
// Date parsing (UTCTime / GeneralizedTime)
// ---------------------------------------------------------------------------

DateTime _parseDerTime(Uint8List bytes, _Asn1Node node) {
  final value =
      String.fromCharCodes(bytes.sublist(node.valueStart, node.valueEnd));
  // Strip any fractional seconds or timezone offset for simplicity.
  var clean = value.replaceAll('Z', '').replaceAll('+', '').replaceAll('-', '');
  // Remove any trailing non-digit characters.
  while (clean.isNotEmpty) {
    final lastCode = clean.codeUnitAt(clean.length - 1);
    if (lastCode >= 0x30 && lastCode <= 0x39) break;
    clean = clean.substring(0, clean.length - 1);
  }

  if (node.tag == 0x17) {
    // UTCTime: YYMMDDHHMMSS
    if (clean.length < 12) clean = clean.padRight(12, '0');
    final year = int.parse(clean.substring(0, 2));
    final fullYear = year >= 50 ? 1900 + year : 2000 + year;
    return DateTime(
      fullYear,
      int.parse(clean.substring(2, 4)),
      int.parse(clean.substring(4, 6)),
      int.parse(clean.substring(6, 8)),
      int.parse(clean.substring(8, 10)),
      int.parse(clean.substring(10, 12)),
    );
  } else if (node.tag == 0x18) {
    // GeneralizedTime: YYYYMMDDHHMMSS
    if (clean.length < 14) clean = clean.padRight(14, '0');
    return DateTime(
      int.parse(clean.substring(0, 4)),
      int.parse(clean.substring(4, 6)),
      int.parse(clean.substring(6, 8)),
      int.parse(clean.substring(8, 10)),
      int.parse(clean.substring(10, 12)),
      int.parse(clean.substring(12, 14)),
    );
  }
  throw FormatException('Unknown time tag: 0x${node.tag.toRadixString(16)}');
}

// ---------------------------------------------------------------------------
// X.509 certificate parsing
// ---------------------------------------------------------------------------

/// Parses a DER-encoded X.509 certificate.
///
/// Performs real DER parsing to extract TBS certificate, signature algorithm,
/// signature value, issuer, subject, validity dates, and subject public key.
///
/// Throws [FormatException] if [derBytes] are not valid DER or the structure
/// is unsupported.
X509Certificate parseX509(List<int> derBytes) {
  final bytes = Uint8List.fromList(derBytes);
  if (bytes.isEmpty || bytes[0] != 0x30) {
    throw FormatException(
      'Invalid DER bytes: expected SEQUENCE tag 0x30, got '
      '${bytes.isEmpty ? "empty" : "0x${bytes[0].toRadixString(16)}"}',
    );
  }

  // Top-level Certificate SEQUENCE
  final certNode = _parseDerNode(bytes, 0);
  final certChildren =
      _parseChildren(bytes, certNode.valueStart, certNode.valueEnd);

  // SECURITY: Reject malformed certificates instead of returning a synthetic
  // certificate that could bypass signature verification.
  if (certChildren.length < 3) {
    throw FormatException(
        'Invalid certificate: insufficient top-level elements');
  }

  // 1. TBSCertificate (SEQUENCE)
  final tbsNode = certChildren[0];
  if (tbsNode.tag != 0x30) {
    throw FormatException('Expected TBSCertificate SEQUENCE');
  }
  final tbsBytes = bytes.sublist(tbsNode.start, tbsNode.end);
  final tbsChildren =
      _parseChildren(bytes, tbsNode.valueStart, tbsNode.valueEnd);

  // Parse TBSCertificate fields.
  // [0] Version, SerialNumber, Signature AlgorithmIdentifier,
  // Issuer Name, Validity, Subject Name, SubjectPublicKeyInfo,
  // optional [1] issuerUniqueID, optional [2] subjectUniqueID, optional [3] extensions
  var tbsIdx = 0;

  // Optional version [0] EXPLICIT
  if (tbsIdx < tbsChildren.length && tbsChildren[tbsIdx].tag == 0xA0) {
    tbsIdx++;
  }

  // SerialNumber
  if (tbsIdx < tbsChildren.length) tbsIdx++;

  // Signature AlgorithmIdentifier
  if (tbsIdx < tbsChildren.length) tbsIdx++;

  // Issuer Name
  List<int> issuerBytes = const <int>[];
  if (tbsIdx < tbsChildren.length) {
    final issuerNode = tbsChildren[tbsIdx];
    if (issuerNode.tag == 0x30) {
      issuerBytes = bytes.sublist(issuerNode.start, issuerNode.end);
    }
    tbsIdx++;
  }

  // Validity SEQUENCE
  DateTime notBefore = DateTime(1970, 1, 1);
  DateTime notAfter = DateTime(2099, 12, 31);
  if (tbsIdx < tbsChildren.length) {
    final validityNode = tbsChildren[tbsIdx];
    if (validityNode.tag == 0x30) {
      final validityChildren =
          _parseChildren(bytes, validityNode.valueStart, validityNode.valueEnd);
      if (validityChildren.isNotEmpty) {
        notBefore = _parseDerTime(bytes, validityChildren[0]);
      }
      if (validityChildren.length > 1) {
        notAfter = _parseDerTime(bytes, validityChildren[1]);
      }
    }
    tbsIdx++;
  }

  // Subject Name
  List<int> subjectBytes = const <int>[];
  if (tbsIdx < tbsChildren.length) {
    final subjectNode = tbsChildren[tbsIdx];
    if (subjectNode.tag == 0x30) {
      subjectBytes = bytes.sublist(subjectNode.start, subjectNode.end);
    }
    tbsIdx++;
  }

  // SubjectPublicKeyInfo
  List<int> spkiBytes = const <int>[];
  if (tbsIdx < tbsChildren.length) {
    final spkiNode = tbsChildren[tbsIdx];
    if (spkiNode.tag == 0x30) {
      spkiBytes = bytes.sublist(spkiNode.start, spkiNode.end);
    }
    tbsIdx++;
  }

  // Extensions [3] EXPLICIT
  final extensions = <String, List<int>>{};
  if (tbsIdx < tbsChildren.length && tbsChildren[tbsIdx].tag == 0xA3) {
    final extWrapperNode = tbsChildren[tbsIdx];
    final extWrapperChildren =
        _parseChildren(bytes, extWrapperNode.valueStart, extWrapperNode.valueEnd);
    // The [3] wrapper contains the Extensions SEQUENCE.
    for (final extensionsSeqNode in extWrapperChildren) {
      if (extensionsSeqNode.tag != 0x30) continue;
      final extensionList =
          _parseChildren(bytes, extensionsSeqNode.valueStart, extensionsSeqNode.valueEnd);
      // Each child of the Extensions SEQUENCE is an individual Extension SEQUENCE.
      for (final extSeqNode in extensionList) {
        if (extSeqNode.tag != 0x30) continue;
        final extChildren =
            _parseChildren(bytes, extSeqNode.valueStart, extSeqNode.valueEnd);
        if (extChildren.isEmpty) continue;
        // First child must be OID
        final oidNode = extChildren[0];
        if (oidNode.tag != 0x06) continue;
        final oidBytes = bytes.sublist(oidNode.valueStart, oidNode.valueEnd);
        final oid = _oidBytesToDotted(oidBytes);
        // Find the OCTET STRING value (skip optional critical BOOLEAN)
        List<int> extValue = const <int>[];
        for (var i = 1; i < extChildren.length; i++) {
          final child = extChildren[i];
          if (child.tag == 0x04) {
            extValue = bytes.sublist(child.valueStart, child.valueEnd);
            break;
          }
        }
        extensions[oid] = Uint8List.fromList(extValue);
      }
    }
    tbsIdx++;
  }

  // 2. Signature AlgorithmIdentifier
  String sigAlg = 'unknown';
  final sigAlgNode = certChildren[1];
  if (sigAlgNode.tag == 0x30) {
    final sigAlgChildren =
        _parseChildren(bytes, sigAlgNode.valueStart, sigAlgNode.valueEnd);
    if (sigAlgChildren.isNotEmpty && sigAlgChildren[0].tag == 0x06) {
      final oidBytes = bytes.sublist(
          sigAlgChildren[0].valueStart, sigAlgChildren[0].valueEnd);
      sigAlg = _oidToAlgorithm(oidBytes);
    }
  }

  // 3. Signature Value (BIT STRING)
  List<int> sigValue = const <int>[];
  final sigValueNode = certChildren[2];
  if (sigValueNode.tag == 0x03) {
    // BIT STRING: first byte is unused bits count, rest is the value.
    if (sigValueNode.length > 1) {
      sigValue =
          bytes.sublist(sigValueNode.valueStart + 1, sigValueNode.valueEnd);
    }
  }

  return X509Certificate(
    tbsCertificate: Uint8List.fromList(tbsBytes),
    signatureAlgorithm: sigAlg,
    signatureValue: Uint8List.fromList(sigValue),
    issuer: Uint8List.fromList(issuerBytes),
    subject: Uint8List.fromList(subjectBytes),
    notBefore: notBefore,
    notAfter: notAfter,
    subjectPublicKeyInfo: Uint8List.fromList(spkiBytes),
    extensions: extensions,
  );
}

/// Looks for the libp2p TLS extension (OID `1.3.6.1.4.1.53594.1.1`) in the
/// certificate's extension map and parses the [SignedKey] protobuf.
///
/// Returns `null` if the extension is not present or cannot be parsed.
Libp2pExtension? parseLibp2pExtension(X509Certificate cert) {
  final raw = cert.extensions[Libp2pExtension.oid];
  if (raw == null || raw.isEmpty) return null;
  try {
    return Libp2pExtension.parse(Uint8List.fromList(raw));
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verifies the signature on an [X509Certificate].
///
/// Delegates to the appropriate [CryptoBackend] verification method
/// based on the certificate's signature algorithm.
///
/// [cert] – the parsed X.509 certificate.
/// [pubKey] – the issuer's public key that should have signed the cert.
/// [backend] – the crypto primitive backend to use for verification.
Future<bool> verifyX509Signature(
  X509Certificate cert,
  PublicKey pubKey,
  CryptoBackend backend,
) async {
  if (cert.signatureAlgorithm == 'ed25519') {
    return backend.ed25519Verify(
        pubKey, cert.tbsCertificate, cert.signatureValue);
  } else if (cert.signatureAlgorithm == 'ecdsaP256') {
    return backend.ecdsaP256Verify(
        pubKey, cert.tbsCertificate, cert.signatureValue);
  } else if (cert.signatureAlgorithm == 'rsaPkcs1Sha256' ||
      cert.signatureAlgorithm == 'rsaPkcs1Sha384') {
    final hash =
        cert.signatureAlgorithm == 'rsaPkcs1Sha256' ? Sha256() : Sha384();
    return backend.rsaPkcs1Verify(
        pubKey, hash, cert.tbsCertificate, cert.signatureValue);
  } else {
    throw UnsupportedError('Signature algorithm: ${cert.signatureAlgorithm}');
  }
}

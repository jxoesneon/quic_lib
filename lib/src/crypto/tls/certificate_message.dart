import 'dart:typed_data';

import 'package:dart_quic/src/crypto/tls/client_hello.dart' show TlsExtension;

/// TLS 1.3 CertificateEntry structure per RFC 8446 Section 4.4.2.
///
/// ```
/// struct {
///     opaque cert_data<1..2^24-1>;
///     Extension extensions<0..2^16-1>;
/// } CertificateEntry;
/// ```
class CertificateEntry {
  final List<int> certData;
  final List<TlsExtension> extensions;

  CertificateEntry({required this.certData, this.extensions = const []});
}

/// TLS 1.3 Certificate structure per RFC 8446 Section 4.4.2.
///
/// ```
/// struct {
///     opaque request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
/// ```
class CertificateMessage {
  /// Empty in server cert, may have data in client cert.
  final List<int> requestContext;

  /// List of certificate entries.
  final List<CertificateEntry> entries;

  CertificateMessage({this.requestContext = const [], required this.entries});

  /// Serialize per RFC 8446 §4.4.2:
  /// uint8 request_context_length
  /// uint8[] request_context
  /// uint24 certificates_length
  /// CertificateEntry[]
  Uint8List serialize() {
    // Calculate total size of all certificate entries
    var entriesLength = 0;
    for (final entry in entries) {
      // cert_data_length (3) + cert_data + extensions_length (2) + extensions
      entriesLength += 3 + entry.certData.length;
      var extLength = 0;
      for (final ext in entry.extensions) {
        extLength += 4 + ext.data.length; // type (2) + length (2) + data
      }
      entriesLength += 2 + extLength;
    }

    final totalLength =
        1 + // request_context_length
        requestContext.length +
        3 + // certificates_length (uint24)
        entriesLength;

    final buffer = Uint8List(totalLength);
    var offset = 0;

    // request_context_length
    buffer[offset++] = requestContext.length;

    // request_context
    for (var i = 0; i < requestContext.length; i++) {
      buffer[offset++] = requestContext[i];
    }

    // certificates_length (uint24, big-endian)
    buffer[offset++] = (entriesLength >> 16) & 0xFF;
    buffer[offset++] = (entriesLength >> 8) & 0xFF;
    buffer[offset++] = entriesLength & 0xFF;

    // CertificateEntry[]
    for (final entry in entries) {
      // cert_data_length (uint24)
      buffer[offset++] = (entry.certData.length >> 16) & 0xFF;
      buffer[offset++] = (entry.certData.length >> 8) & 0xFF;
      buffer[offset++] = entry.certData.length & 0xFF;

      // cert_data
      for (var i = 0; i < entry.certData.length; i++) {
        buffer[offset++] = entry.certData[i];
      }

      // extensions_length (uint16)
      var extLength = 0;
      for (final ext in entry.extensions) {
        extLength += 4 + ext.data.length;
      }
      buffer[offset++] = (extLength >> 8) & 0xFF;
      buffer[offset++] = extLength & 0xFF;

      // extensions
      for (final ext in entry.extensions) {
        buffer[offset++] = (ext.type >> 8) & 0xFF;
        buffer[offset++] = ext.type & 0xFF;
        buffer[offset++] = (ext.data.length >> 8) & 0xFF;
        buffer[offset++] = ext.data.length & 0xFF;
        for (var i = 0; i < ext.data.length; i++) {
          buffer[offset++] = ext.data[i];
        }
      }
    }

    return buffer;
  }

  /// Parse from bytes.
  static CertificateMessage parse(Uint8List bytes) {
    var offset = 0;

    // request_context_length
    final requestContextLength = bytes[offset++];

    // request_context
    final requestContext =
        bytes.sublist(offset, offset + requestContextLength).toList();
    offset += requestContextLength;

    // certificates_length (uint24)
    final entriesLength =
        (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
    offset += 3;

    final entriesEnd = offset + entriesLength;
    final entries = <CertificateEntry>[];

    while (offset < entriesEnd) {
      // cert_data_length (uint24)
      final certDataLength = (bytes[offset] << 16) |
          (bytes[offset + 1] << 8) |
          bytes[offset + 2];
      offset += 3;

      // cert_data
      final certData =
          bytes.sublist(offset, offset + certDataLength).toList();
      offset += certDataLength;

      // extensions_length (uint16)
      final extensionsLength = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2;

      // extensions
      final extensions = <TlsExtension>[];
      final extensionsEnd = offset + extensionsLength;
      while (offset < extensionsEnd) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        offset += 2;
        final extDataLength = (bytes[offset] << 8) | bytes[offset + 1];
        offset += 2;
        final extData =
            bytes.sublist(offset, offset + extDataLength).toList();
        offset += extDataLength;
        extensions.add(TlsExtension(type: extType, data: extData));
      }

      entries.add(CertificateEntry(certData: certData, extensions: extensions));
    }

    return CertificateMessage(
      requestContext: requestContext,
      entries: entries,
    );
  }
}

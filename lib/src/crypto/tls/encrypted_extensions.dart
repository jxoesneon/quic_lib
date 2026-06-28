import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/client_hello.dart';

/// TLS 1.3 EncryptedExtensions structure per RFC 8446 Section 4.3.1.
///
/// EncryptedExtensions contains a list of extensions that are not
/// sent in the ServerHello because they are not needed to establish
/// the cryptographic context.
///
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
class EncryptedExtensions {
  final List<TlsExtension> extensions;

  EncryptedExtensions({required this.extensions});

  /// Serialize: uint16 extensions_length + Extension[]
  Uint8List serialize() {
    var extensionsLength = 0;
    for (final ext in extensions) {
      extensionsLength += 4 + ext.data.length; // type (2) + length (2) + data
    }

    final totalLength = 2 + // extensions_length
        extensionsLength;

    final buffer = ByteData(totalLength);
    var offset = 0;

    // extensions_length
    buffer.setUint16(offset, extensionsLength, Endian.big);
    offset += 2;

    // extensions
    for (final ext in extensions) {
      buffer.setUint16(offset, ext.type, Endian.big);
      offset += 2;
      buffer.setUint16(offset, ext.data.length, Endian.big);
      offset += 2;
      for (var i = 0; i < ext.data.length; i++) {
        buffer.setUint8(offset + i, ext.data[i]);
      }
      offset += ext.data.length;
    }

    return buffer.buffer.asUint8List();
  }

  /// The negotiated ALPN protocol, if present.
  ///
  /// Parses the ALPN extension (type `0x0010`) from the server's
  /// EncryptedExtensions. Returns `null` if the extension is absent or
  /// malformed.
  String? get alpnProtocol {
    for (final ext in extensions) {
      if (ext.type == 0x0010 && ext.data.isNotEmpty) {
        final nameLen = ext.data[0];
        if (1 + nameLen <= ext.data.length) {
          return String.fromCharCodes(ext.data.sublist(1, 1 + nameLen));
        }
      }
    }
    return null;
  }

  /// The supported groups advertised by the server, if present.
  ///
  /// Parses the `supported_groups` extension (type `0x000a`) from the
  /// server's EncryptedExtensions. Returns an empty list if the extension
  /// is absent or malformed.
  List<int> get supportedGroups {
    for (final ext in extensions) {
      if (ext.type == 0x000a && ext.data.length >= 2) {
        final listLen = (ext.data[0] << 8) | ext.data[1];
        if (2 + listLen > ext.data.length) return const [];
        final groups = <int>[];
        var offset = 2;
        final end = 2 + listLen;
        while (offset + 2 <= end) {
          groups.add((ext.data[offset] << 8) | ext.data[offset + 1]);
          offset += 2;
        }
        return groups;
      }
    }
    return const [];
  }

  /// The server name indicated by the server in response to the client's
  /// SNI, if present.
  ///
  /// Parses the SNI extension (type `0x0000`) from the server's
  /// EncryptedExtensions. Returns `null` if the extension is absent or
  /// malformed.
  String? get selectedServerName {
    for (final ext in extensions) {
      if (ext.type == 0x0000 && ext.data.length >= 2) {
        final listLen = (ext.data[0] << 8) | ext.data[1];
        if (2 + listLen > ext.data.length) return null;
        var offset = 2;
        final end = 2 + listLen;
        // Each entry: uint8 name_type + uint16 name_length + name
        if (offset + 3 > end) return null;
        final nameType = ext.data[offset];
        if (nameType != 0) return null; // only host_name supported
        offset += 1;
        final nameLen = (ext.data[offset] << 8) | ext.data[offset + 1];
        offset += 2;
        if (offset + nameLen > end) return null;
        return String.fromCharCodes(ext.data.sublist(offset, offset + nameLen));
      }
    }
    return null;
  }

  /// Parse from bytes.
  static EncryptedExtensions parse(Uint8List bytes) {
    if (bytes.length < 2) {
      throw ArgumentError(
        'EncryptedExtensions must be at least 2 bytes, got ${bytes.length}',
      );
    }

    final reader = ByteData.sublistView(bytes);
    var offset = 0;

    // extensions_length
    final extensionsLength = reader.getUint16(offset, Endian.big);
    offset += 2;

    if (bytes.length < 2 + extensionsLength) {
      throw ArgumentError(
        'EncryptedExtensions truncated: expected ${2 + extensionsLength} bytes, got ${bytes.length}',
      );
    }

    final extensions = <TlsExtension>[];
    final endOffset = offset + extensionsLength;

    while (offset < endOffset) {
      if (offset + 4 > endOffset) {
        throw ArgumentError(
          'Extension header truncated at offset $offset',
        );
      }

      final extType = reader.getUint16(offset, Endian.big);
      offset += 2;

      final extLength = reader.getUint16(offset, Endian.big);
      offset += 2;

      if (offset + extLength > endOffset) {
        throw ArgumentError(
          'Extension data truncated: type 0x${extType.toRadixString(16).padLeft(4, '0')}, expected $extLength bytes at offset $offset',
        );
      }

      final extData = bytes.sublist(offset, offset + extLength);
      offset += extLength;

      extensions.add(TlsExtension(type: extType, data: extData));
    }

    // Ensure we consumed exactly the declared length.
    if (offset != endOffset) {
      throw ArgumentError(
        'EncryptedExtensions length mismatch: consumed $offset bytes, expected $endOffset',
      );
    }

    return EncryptedExtensions(extensions: extensions);
  }
}

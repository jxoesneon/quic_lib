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

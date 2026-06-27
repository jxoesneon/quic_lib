import 'dart:typed_data';

/// TLS 1.3 ClientHello structure per RFC 8446 Section 4.1.2.
///
/// This class only implements the data structure and serializer; no
/// cryptographic operations are performed.
class ClientHello {
  /// Legacy version (always 0x0303 for TLS 1.3 compatibility).
  final int legacyVersion;

  /// 32 bytes of random data.
  final List<int> random;

  /// Legacy session ID (empty for TLS 1.3).
  final List<int> legacySessionId;

  /// List of supported cipher suites.
  final List<CipherSuite> cipherSuites;

  /// Legacy compression methods (always [0x00] for TLS 1.3).
  final List<int> legacyCompressionMethods;

  /// List of extensions.
  final List<TlsExtension> extensions;

  ClientHello({
    required this.random,
    required this.cipherSuites,
    required this.extensions,
    this.legacyVersion = 0x0303,
    this.legacySessionId = const [],
    this.legacyCompressionMethods = const [0x00],
  });

  /// Serializes the ClientHello to bytes in network (big-endian) order.
  Uint8List serialize() {
    final sessionIdLength = legacySessionId.length;
    final cipherSuitesLength = cipherSuites.length * 2;
    final compressionMethodsLength = legacyCompressionMethods.length;

    var extensionsLength = 0;
    for (final ext in extensions) {
      extensionsLength += 4 + ext.data.length; // type (2) + length (2) + data
    }

    final totalLength =
        2 + // legacy_version
        32 + // random
        1 + // legacy_session_id_length
        sessionIdLength +
        2 + // cipher_suites_length
        cipherSuitesLength +
        1 + // legacy_compression_methods_length
        compressionMethodsLength +
        2 + // extensions_length
        extensionsLength;

    final buffer = ByteData(totalLength);
    var offset = 0;

    // legacy_version
    buffer.setUint16(offset, legacyVersion, Endian.big);
    offset += 2;

    // random
    for (var i = 0; i < 32; i++) {
      buffer.setUint8(offset + i, random[i]);
    }
    offset += 32;

    // legacy_session_id_length
    buffer.setUint8(offset, sessionIdLength);
    offset += 1;

    // legacy_session_id
    for (var i = 0; i < sessionIdLength; i++) {
      buffer.setUint8(offset + i, legacySessionId[i]);
    }
    offset += sessionIdLength;

    // cipher_suites_length
    buffer.setUint16(offset, cipherSuitesLength, Endian.big);
    offset += 2;

    // cipher_suites
    for (final cs in cipherSuites) {
      buffer.setUint16(offset, cs.id, Endian.big);
      offset += 2;
    }

    // legacy_compression_methods_length
    buffer.setUint8(offset, compressionMethodsLength);
    offset += 1;

    // legacy_compression_methods
    for (var i = 0; i < compressionMethodsLength; i++) {
      buffer.setUint8(offset + i, legacyCompressionMethods[i]);
    }
    offset += compressionMethodsLength;

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
}

/// TLS cipher suite identifier (2 bytes).
class CipherSuite {
  final int id;
  const CipherSuite(this.id);

  static const tlsAes128GcmSha256 = CipherSuite(0x1301);
  static const tlsAes256GcmSha384 = CipherSuite(0x1302);
  static const tlsChacha20Poly1305Sha256 = CipherSuite(0x1303);
}

/// TLS extension as a generic type + opaque data block.
class TlsExtension {
  final int type;
  final List<int> data;

  TlsExtension({required this.type, required this.data});
}

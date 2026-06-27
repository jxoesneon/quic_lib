import 'dart:typed_data';

import 'package:dart_quic/src/crypto/tls/client_hello.dart'
    show CipherSuite, TlsExtension;

/// TLS 1.3 ServerHello structure per RFC 8446 Section 4.1.3.
///
/// This class only implements the data structure and serializer; no
/// cryptographic operations are performed.
class ServerHello {
  /// Legacy version (always 0x0303 for TLS 1.3 compatibility).
  final int legacyVersion;

  /// 32 bytes of random data.
  final List<int> random;

  /// Legacy session ID echo (empty for TLS 1.3).
  final List<int> legacySessionIdEcho;

  /// Selected cipher suite.
  final CipherSuite cipherSuite;

  /// Legacy compression method (always 0x00 for TLS 1.3).
  final int legacyCompressionMethod;

  /// List of extensions.
  final List<TlsExtension> extensions;

  ServerHello({
    required this.random,
    required this.cipherSuite,
    required this.extensions,
    this.legacyVersion = 0x0303,
    this.legacySessionIdEcho = const [],
    this.legacyCompressionMethod = 0x00,
  });

  /// Serializes the ServerHello to bytes in network (big-endian) order.
  Uint8List serialize() {
    final sessionIdLength = legacySessionIdEcho.length;

    var extensionsLength = 0;
    for (final ext in extensions) {
      extensionsLength += 4 + ext.data.length; // type (2) + length (2) + data
    }

    final totalLength =
        2 + // legacy_version
        32 + // random
        1 + // legacy_session_id_echo_length
        sessionIdLength +
        2 + // cipher_suite
        1 + // legacy_compression_method
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

    // legacy_session_id_echo_length
    buffer.setUint8(offset, sessionIdLength);
    offset += 1;

    // legacy_session_id_echo
    for (var i = 0; i < sessionIdLength; i++) {
      buffer.setUint8(offset + i, legacySessionIdEcho[i]);
    }
    offset += sessionIdLength;

    // cipher_suite
    buffer.setUint16(offset, cipherSuite.id, Endian.big);
    offset += 2;

    // legacy_compression_method
    buffer.setUint8(offset, legacyCompressionMethod);
    offset += 1;

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

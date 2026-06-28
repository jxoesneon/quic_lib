import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';

/// Builder for TLS 1.3 handshake messages in wire format:
/// `type(1) + length(3) + payload(length)`.
///
/// This is intended for testing the [CryptoFrameHandler] pipeline, where
/// fully-formed handshake messages are needed but real cryptographic
/// operations are not required.
class TlsMessageBuilder {
  /// Builds a ClientHello handshake message (type 0x01).
  ///
  /// [random] must be 32 bytes.
  /// [legacySessionId] is typically empty for TLS 1.3.
  /// [cipherSuites] is a list of 2-byte cipher suite identifiers.
  /// [extensions] is a list of pre-serialized extension byte arrays.
  static Uint8List buildClientHello(
    Uint8List random,
    Uint8List legacySessionId,
    List<int> cipherSuites,
    List<Uint8List> extensions,
  ) {
    if (random.length != 32) {
      throw ArgumentError('random must be 32 bytes, got ${random.length}');
    }

    final extensionsLength =
        extensions.fold<int>(0, (sum, e) => sum + e.length);

    final payloadLength = 2 + // legacy_version
        32 + // random
        1 + // legacy_session_id_length
        legacySessionId.length +
        2 + // cipher_suites_length
        cipherSuites.length * 2 +
        1 + // legacy_compression_methods_length
        1 + // legacy_compression_methods (0x00)
        2 + // extensions_length
        extensionsLength;

    final totalLength = 1 + 3 + payloadLength;
    final buffer = ByteData(totalLength);
    var offset = 0;

    // type
    buffer.setUint8(offset, TlsHandshakeType.clientHello.value);
    offset += 1;

    // length (3 bytes, big-endian)
    buffer.setUint8(offset, (payloadLength >> 16) & 0xFF);
    buffer.setUint8(offset + 1, (payloadLength >> 8) & 0xFF);
    buffer.setUint8(offset + 2, payloadLength & 0xFF);
    offset += 3;

    // payload: legacy_version
    buffer.setUint16(offset, 0x0303, Endian.big);
    offset += 2;

    // random
    for (var i = 0; i < 32; i++) {
      buffer.setUint8(offset + i, random[i]);
    }
    offset += 32;

    // legacy_session_id_length
    buffer.setUint8(offset, legacySessionId.length);
    offset += 1;

    // legacy_session_id
    for (var i = 0; i < legacySessionId.length; i++) {
      buffer.setUint8(offset + i, legacySessionId[i]);
    }
    offset += legacySessionId.length;

    // cipher_suites_length
    buffer.setUint16(offset, cipherSuites.length * 2, Endian.big);
    offset += 2;

    // cipher_suites
    for (final cs in cipherSuites) {
      buffer.setUint16(offset, cs, Endian.big);
      offset += 2;
    }

    // legacy_compression_methods_length
    buffer.setUint8(offset, 1);
    offset += 1;

    // legacy_compression_methods
    buffer.setUint8(offset, 0x00);
    offset += 1;

    // extensions_length
    buffer.setUint16(offset, extensionsLength, Endian.big);
    offset += 2;

    // extensions
    for (final ext in extensions) {
      for (var i = 0; i < ext.length; i++) {
        buffer.setUint8(offset + i, ext[i]);
      }
      offset += ext.length;
    }

    return buffer.buffer.asUint8List();
  }

  /// Builds a ServerHello handshake message (type 0x02).
  ///
  /// [random] must be 32 bytes.
  /// [legacySessionId] is the echoed session ID (typically empty for TLS 1.3).
  /// [cipherSuite] is the selected 2-byte cipher suite identifier.
  /// [extensions] is a list of pre-serialized extension byte arrays.
  static Uint8List buildServerHello(
    Uint8List random,
    Uint8List legacySessionId,
    int cipherSuite,
    List<Uint8List> extensions,
  ) {
    if (random.length != 32) {
      throw ArgumentError('random must be 32 bytes, got ${random.length}');
    }

    final extensionsLength =
        extensions.fold<int>(0, (sum, e) => sum + e.length);

    final payloadLength = 2 + // legacy_version
        32 + // random
        1 + // legacy_session_id_echo_length
        legacySessionId.length +
        2 + // cipher_suite
        1 + // legacy_compression_method
        2 + // extensions_length
        extensionsLength;

    final totalLength = 1 + 3 + payloadLength;
    final buffer = ByteData(totalLength);
    var offset = 0;

    // type
    buffer.setUint8(offset, TlsHandshakeType.serverHello.value);
    offset += 1;

    // length (3 bytes, big-endian)
    buffer.setUint8(offset, (payloadLength >> 16) & 0xFF);
    buffer.setUint8(offset + 1, (payloadLength >> 8) & 0xFF);
    buffer.setUint8(offset + 2, payloadLength & 0xFF);
    offset += 3;

    // payload: legacy_version
    buffer.setUint16(offset, 0x0303, Endian.big);
    offset += 2;

    // random
    for (var i = 0; i < 32; i++) {
      buffer.setUint8(offset + i, random[i]);
    }
    offset += 32;

    // legacy_session_id_echo_length
    buffer.setUint8(offset, legacySessionId.length);
    offset += 1;

    // legacy_session_id_echo
    for (var i = 0; i < legacySessionId.length; i++) {
      buffer.setUint8(offset + i, legacySessionId[i]);
    }
    offset += legacySessionId.length;

    // cipher_suite
    buffer.setUint16(offset, cipherSuite, Endian.big);
    offset += 2;

    // legacy_compression_method
    buffer.setUint8(offset, 0x00);
    offset += 1;

    // extensions_length
    buffer.setUint16(offset, extensionsLength, Endian.big);
    offset += 2;

    // extensions
    for (final ext in extensions) {
      for (var i = 0; i < ext.length; i++) {
        buffer.setUint8(offset + i, ext[i]);
      }
      offset += ext.length;
    }

    return buffer.buffer.asUint8List();
  }

  /// Builds a Finished handshake message (type 0x14).
  ///
  /// [verifyData] is the raw verify_data bytes.
  static Uint8List buildFinished(Uint8List verifyData) {
    final payloadLength = verifyData.length;
    final totalLength = 1 + 3 + payloadLength;
    final buffer = ByteData(totalLength);

    // type
    buffer.setUint8(0, TlsHandshakeType.finished.value);

    // length (3 bytes, big-endian)
    buffer.setUint8(1, (payloadLength >> 16) & 0xFF);
    buffer.setUint8(2, (payloadLength >> 8) & 0xFF);
    buffer.setUint8(3, payloadLength & 0xFF);

    // payload
    for (var i = 0; i < verifyData.length; i++) {
      buffer.setUint8(4 + i, verifyData[i]);
    }

    return buffer.buffer.asUint8List();
  }
}

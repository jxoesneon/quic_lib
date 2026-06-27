import 'dart:typed_data';

import 'tls_handshake_types.dart';

/// Look up a [TlsHandshakeType] from its wire value.
TlsHandshakeType? _lookupType(int byte) {
  for (final type in TlsHandshakeType.values) {
    if (type.value == byte) return type;
  }
  return null;
}

/// Parse the TLS handshake message type from the first byte of [message].
///
/// Returns `null` if the message is empty or the byte does not map to a known
/// [TlsHandshakeType].
TlsHandshakeType? parseMessageType(Uint8List message) {
  if (message.isEmpty) return null;
  return _lookupType(message[0]);
}

/// Parse a complete TLS 1.3 handshake message.
///
/// Wire format: `type(1) + length(3) + payload(length)`.
///
/// Returns a record with the parsed [TlsHandshakeType] and the payload bytes.
///
/// Throws [FormatException] for:
/// - empty messages,
/// - messages shorter than the 4-byte header,
/// - unknown handshake types,
/// - payloads shorter than the declared length.
({TlsHandshakeType type, Uint8List payload}) parseMessage(Uint8List message) {
  if (message.isEmpty) {
    throw FormatException('TLS handshake message is empty');
  }
  if (message.length < 4) {
    throw FormatException(
      'TLS handshake message too short for length header: ${message.length} bytes',
    );
  }

  final type = _lookupType(message[0]);
  if (type == null) {
    throw FormatException(
      'Unknown TLS handshake type: 0x${message[0].toRadixString(16).padLeft(2, '0')}',
    );
  }

  final length = (message[1] << 16) | (message[2] << 8) | message[3];
  if (message.length < 4 + length) {
    throw FormatException(
      'TLS handshake message truncated: '
      'expected ${4 + length} bytes, got ${message.length}',
    );
  }

  final payload = message.sublist(4, 4 + length);
  return (type: type, payload: payload);
}

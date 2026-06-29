import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/client_hello.dart';

/// RFC 8446 NewSessionTicket handshake message.
///
/// Sent by the server after the handshake completes to enable session
/// resumption and 0-RTT data on subsequent connections.
///
/// See also:
/// - [ClientHello] — can include PSK extensions referencing this ticket
/// - [ZeroRttHelper] — derives 0-RTT keys from the PSK
/// - RFC 8446 Section 4.6.1 — NewSessionTicket message format
class NewSessionTicket {
  /// Ticket lifetime in seconds (maximum 604800 = 7 days per RFC 8446).
  final int ticketLifetime;

  /// Random value added to ticket age to prevent tracking.
  final int ticketAgeAdd;

  /// Per-ticket nonce used in PSK derivation.
  final Uint8List ticketNonce;

  /// Opaque ticket data used by the server to resume the session.
  final Uint8List ticket;

  /// Optional extensions (commonly `early_data` for 0-RTT).
  final List<TlsExtension> extensions;

  NewSessionTicket({
    required this.ticketLifetime,
    required this.ticketAgeAdd,
    required this.ticketNonce,
    required this.ticket,
    this.extensions = const [],
  });

  Uint8List serialize() {
    final bb = BytesBuilder();
    // uint32 ticket_lifetime
    bb.addByte((ticketLifetime >> 24) & 0xFF);
    bb.addByte((ticketLifetime >> 16) & 0xFF);
    bb.addByte((ticketLifetime >> 8) & 0xFF);
    bb.addByte(ticketLifetime & 0xFF);
    // uint32 ticket_age_add
    bb.addByte((ticketAgeAdd >> 24) & 0xFF);
    bb.addByte((ticketAgeAdd >> 16) & 0xFF);
    bb.addByte((ticketAgeAdd >> 8) & 0xFF);
    bb.addByte(ticketAgeAdd & 0xFF);
    // uint8 ticket_nonce_length + ticket_nonce
    bb.addByte(ticketNonce.length);
    bb.add(ticketNonce);
    // uint16 ticket_length + ticket
    bb.addByte((ticket.length >> 8) & 0xFF);
    bb.addByte(ticket.length & 0xFF);
    bb.add(ticket);
    // uint16 extensions_length + extensions
    var extensionsLength = 0;
    for (final ext in extensions) {
      extensionsLength += 4 + ext.data.length;
    }
    bb.addByte((extensionsLength >> 8) & 0xFF);
    bb.addByte(extensionsLength & 0xFF);
    for (final ext in extensions) {
      bb.addByte((ext.type >> 8) & 0xFF);
      bb.addByte(ext.type & 0xFF);
      bb.addByte((ext.data.length >> 8) & 0xFF);
      bb.addByte(ext.data.length & 0xFF);
      bb.add(ext.data);
    }
    return Uint8List.fromList(bb.toBytes());
  }

  /// Parse a [NewSessionTicket] from [bytes].
  static NewSessionTicket parse(Uint8List bytes) {
    if (bytes.length < 10) {
      throw ArgumentError(
        'NewSessionTicket must be at least 10 bytes, got ${bytes.length}',
      );
    }
    final reader = ByteData.sublistView(bytes);
    var offset = 0;

    // ticket_lifetime
    final ticketLifetime = reader.getUint32(offset, Endian.big);
    offset += 4;

    // ticket_age_add
    final ticketAgeAdd = reader.getUint32(offset, Endian.big);
    offset += 4;

    // ticket_nonce
    final ticketNonceLen = reader.getUint8(offset);
    offset += 1;
    if (offset + ticketNonceLen > bytes.length) {
      throw ArgumentError('Ticket nonce truncated');
    }
    final ticketNonce = bytes.sublist(offset, offset + ticketNonceLen);
    offset += ticketNonceLen;

    // ticket
    if (offset + 2 > bytes.length) {
      throw ArgumentError('Ticket length truncated');
    }
    final ticketLen = reader.getUint16(offset, Endian.big);
    offset += 2;
    if (offset + ticketLen > bytes.length) {
      throw ArgumentError('Ticket truncated');
    }
    final ticket = bytes.sublist(offset, offset + ticketLen);
    offset += ticketLen;

    // extensions
    if (offset + 2 > bytes.length) {
      throw ArgumentError('Extensions length truncated');
    }
    final extensionsLength = reader.getUint16(offset, Endian.big);
    offset += 2;
    final extensionsEnd = offset + extensionsLength;
    if (extensionsEnd > bytes.length) {
      throw ArgumentError('Extensions truncated');
    }

    final extensions = <TlsExtension>[];
    while (offset < extensionsEnd) {
      if (offset + 4 > extensionsEnd) {
        throw ArgumentError('Extension header truncated');
      }
      final extType = reader.getUint16(offset, Endian.big);
      offset += 2;
      final extLength = reader.getUint16(offset, Endian.big);
      offset += 2;
      if (offset + extLength > extensionsEnd) {
        throw ArgumentError('Extension data truncated');
      }
      final extData = bytes.sublist(offset, offset + extLength);
      offset += extLength;
      extensions.add(TlsExtension(type: extType, data: extData));
    }

    return NewSessionTicket(
      ticketLifetime: ticketLifetime,
      ticketAgeAdd: ticketAgeAdd,
      ticketNonce: Uint8List.fromList(ticketNonce),
      ticket: Uint8List.fromList(ticket),
      extensions: extensions,
    );
  }
}

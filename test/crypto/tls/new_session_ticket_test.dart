import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:quic_lib/src/crypto/tls/new_session_ticket.dart';

void main() {
  group('NewSessionTicket', () {
    test('serialize round-trip with parse', () {
      final ticket = NewSessionTicket(
        ticketLifetime: 7200,
        ticketAgeAdd: 0x12345678,
        ticketNonce: Uint8List.fromList([0x01, 0x02, 0x03]),
        ticket: Uint8List.fromList([0xAB, 0xCD, 0xEF]),
        extensions: [
          TlsExtension(type: 0x002a, data: []),
        ],
      );

      final bytes = ticket.serialize();
      final parsed = NewSessionTicket.parse(bytes);

      expect(parsed.ticketLifetime, equals(7200));
      expect(parsed.ticketAgeAdd, equals(0x12345678));
      expect(parsed.ticketNonce, equals([0x01, 0x02, 0x03]));
      expect(parsed.ticket, equals([0xAB, 0xCD, 0xEF]));
      expect(parsed.extensions.length, equals(1));
      expect(parsed.extensions[0].type, equals(0x002a));
      expect(parsed.extensions[0].data, isEmpty);
    });

    test('fields are preserved', () {
      final ticket = NewSessionTicket(
        ticketLifetime: 3600,
        ticketAgeAdd: 0xDEADBEEF,
        ticketNonce: Uint8List.fromList([0xAA]),
        ticket: Uint8List.fromList([0x11, 0x22]),
      );

      expect(ticket.ticketLifetime, equals(3600));
      expect(ticket.ticketAgeAdd, equals(0xDEADBEEF));
      expect(ticket.ticketNonce, equals([0xAA]));
      expect(ticket.ticket, equals([0x11, 0x22]));
      expect(ticket.extensions, isEmpty);
    });

    test('empty extensions round-trip', () {
      final ticket = NewSessionTicket(
        ticketLifetime: 0,
        ticketAgeAdd: 0,
        ticketNonce: Uint8List(0),
        ticket: Uint8List(0),
      );

      final bytes = ticket.serialize();
      final parsed = NewSessionTicket.parse(bytes);

      expect(parsed.ticketLifetime, equals(0));
      expect(parsed.ticketAgeAdd, equals(0));
      expect(parsed.ticketNonce, isEmpty);
      expect(parsed.ticket, isEmpty);
      expect(parsed.extensions, isEmpty);
    });

    test('parse rejects truncated data', () {
      expect(
        () => NewSessionTicket.parse(Uint8List.fromList([0x00, 0x00])),
        throwsArgumentError,
      );
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/packet/retry_integrity_tag.dart';
import 'package:quic_lib/src/crypto/retry_token_generator.dart';
import 'package:quic_lib/src/crypto/tls/session_ticket_store.dart';
import 'package:quic_lib/src/http3/http3_body_streaming.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/wire/retry_packet_builder.dart';
import 'package:test/test.dart';

class FakeQuicConnection {
  int _nextStreamId = 0;
  int openBidirectionalStream() {
    final id = _nextStreamId;
    _nextStreamId += 4;
    return id;
  }
}

/// Integration tests for dart_quic v0.3.0 features.
void main() {
  final backend = DefaultCryptoBackend();

  group('Retry Token & Packet Integration', () {
    test('RetryTokenGenerator generate + validate round-trip', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final now = DateTime.now().millisecondsSinceEpoch;
      final clientAddr = [192, 168, 1, 1];
      final dcid = [0xDE, 0xAD, 0xBE, 0xEF];

      final token = await gen.generate(clientAddr, dcid, now);
      expect(token, isNotEmpty);

      final valid = await gen.validate(token, clientAddr, dcid);
      expect(valid, isTrue);
    });

    test('RetryPacketBuilder builds a valid Retry packet', () async {
      const version = 0x00000001;
      final originalDcid = [0xAB, 0xCD, 0xEF, 0x01];
      final retryScid = [0x12, 0x34, 0x56, 0x78];
      final retryToken = [0x99, 0x88, 0x77, 0x66];

      final packet = await RetryPacketBuilder.build(
        version: version,
        originalDestinationConnectionId: originalDcid,
        retrySourceConnectionId: retryScid,
        retryToken: retryToken,
        backend: backend,
      );

      expect(packet, isNotEmpty);
      // Packet must contain header fields + token + 16-byte integrity tag.
      expect(packet.length, greaterThan(16));
    });

    test('RetryIntegrityTag.verify succeeds on built packet', () async {
      const version = 0x00000001;
      final originalDcid = [0xAB, 0xCD, 0xEF, 0x01];
      final retryScid = [0x12, 0x34, 0x56, 0x78];
      final retryToken = [0x99, 0x88, 0x77, 0x66];

      final packet = await RetryPacketBuilder.build(
        version: version,
        originalDestinationConnectionId: originalDcid,
        retrySourceConnectionId: retryScid,
        retryToken: retryToken,
        backend: backend,
      );

      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: packet,
        backend: backend,
      );

      expect(valid, isTrue);
    });
  });

  group('HTTP/3 Body Streaming', () {
    test('Http3Connection.sendBody + getBody streams data', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      const streamId = 4;
      final data1 = Uint8List.fromList([0x01, 0x02, 0x03]);
      final data2 = Uint8List.fromList([0x04, 0x05, 0x06]);

      conn.sendBody(streamId, data1);
      conn.sendBody(streamId, data2);

      final body = conn.getBody(streamId);
      expect(body, isNotNull);
      expect(
        body,
        equals(Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])),
      );
    });
  });

  group('Session Ticket Store', () {
    test('SessionTicketStore stores and retrieves tickets', () {
      final store = SessionTicketStore();
      const identifier = 'test-session-1';
      final ticket = Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD]);

      store.store(identifier, ticket);
      final retrieved = store.retrieve(identifier);

      expect(retrieved, isNotNull);
      expect(retrieved, equals(ticket));

      // Verify the returned ticket is a defensive copy.
      ticket[0] = 0xFF;
      expect(retrieved![0], equals(0xAA));
    });
  });
}

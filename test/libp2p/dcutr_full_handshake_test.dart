import 'dart:io';
import 'dart:typed_data';

import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/packet/retry_integrity_tag.dart';
import 'package:quic_lib/src/io/udp_socket.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/retry_packet_builder.dart';
import 'package:test/test.dart';

void main() {
  group('DCUtR full client-server handshake with Retry', () {
    test('Initial -> Retry -> Initial with token packet flow', () async {
      // Bind two real UDP sockets to simulate client (A) and server (B).
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() {
        socketA.close();
        socketB.close();
      });

      final backend = DefaultCryptoBackend();

      const version = 0x00000001; // QUIC v1
      final dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
      final scid = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
      final retryScid = [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];
      final retryToken = [0xAB, 0xCD, 0xEF];

      // ------------------------------------------------------------------
      // Step 1: Peer A sends an Initial packet to Peer B.
      // ------------------------------------------------------------------
      final bReceivedInitial = socketB.incoming.first;

      final initialHeader = LongHeader(
        version: version,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        packetNumber: 0,
        payload: const [],
        token: null,
      );
      final initialPacket =
          PacketBuilder.build(initialHeader, [PaddingFrame(length: 4)]);
      socketA.send(
          initialPacket, InternetAddress.loopbackIPv4, socketB.localPort);

      // ------------------------------------------------------------------
      // Step 2: Peer B receives Initial and responds with a Retry packet.
      // ------------------------------------------------------------------
      final initialDatagram = await bReceivedInitial;
      expect(initialDatagram.data, isNotEmpty);

      final parsedInitial = PacketHeaderParser.parse(
        initialDatagram.data,
        destinationConnectionIdLength: dcid.length,
      );
      expect(parsedInitial, isA<LongHeader>());
      expect((parsedInitial as LongHeader).packetType,
          equals(LongHeader.typeInitial));

      final aReceivedRetry = socketA.incoming.first;

      final retryPacket = await RetryPacketBuilder.build(
        version: version,
        originalDestinationConnectionId: dcid,
        retrySourceConnectionId: retryScid,
        retryToken: retryToken,
        backend: backend,
      );
      socketB.send(
          retryPacket, InternetAddress.loopbackIPv4, socketA.localPort);

      // ------------------------------------------------------------------
      // Step 3: Peer A receives Retry and verifies it.
      // ------------------------------------------------------------------
      final retryDatagram = await aReceivedRetry;
      expect(retryDatagram.data, isNotEmpty);

      final parsedRetry = PacketHeaderParser.parse(
        retryDatagram.data,
        destinationConnectionIdLength: dcid.length,
      );
      expect(parsedRetry, isA<LongHeader>());
      final retryHeader = parsedRetry as LongHeader;
      expect(retryHeader.packetType, equals(LongHeader.typeRetry));
      expect(retryHeader.payload, equals(retryToken));

      // Verify the retry integrity tag is valid.
      final tagValid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: dcid,
        retryPacket: retryDatagram.data,
        backend: backend,
      );
      expect(tagValid, isTrue);

      // ------------------------------------------------------------------
      // Step 4: Peer A resends an Initial with the token from the Retry.
      // ------------------------------------------------------------------
      final bReceivedResent = socketB.incoming.first;

      final resentHeader = LongHeader(
        version: version,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: retryScid,
        sourceConnectionId: scid,
        packetNumber: 1,
        payload: const [],
        token: retryToken,
      );
      final resentPacket =
          PacketBuilder.build(resentHeader, [PaddingFrame(length: 4)]);
      socketA.send(
          resentPacket, InternetAddress.loopbackIPv4, socketB.localPort);

      // ------------------------------------------------------------------
      // Step 5: Peer B receives the resent Initial and verifies the token.
      // ------------------------------------------------------------------
      final resentDatagram = await bReceivedResent;
      expect(resentDatagram.data, isNotEmpty);

      final parsedResent = PacketHeaderParser.parse(
        resentDatagram.data,
        destinationConnectionIdLength: retryScid.length,
      );
      expect(parsedResent, isA<LongHeader>());
      final resentLong = parsedResent as LongHeader;
      expect(resentLong.packetType, equals(LongHeader.typeInitial));
      expect(resentLong.token, equals(retryToken));
    });
  });
}

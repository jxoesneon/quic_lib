import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/io/quic_endpoint.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:dart_quic/src/wire/packet_header.dart';
import 'package:dart_quic/src/wire/packet_builder.dart';

void main() {
  group('QuicEndpoint rebindToAddress', () {
    test('rebindToAddress validates and updates remote address', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final conn = await endpoint.connect(InternetAddress.loopbackIPv4, 12345);

      final newAddr = InternetAddress.loopbackIPv4;
      final newPort = 54321;

      // Start rebind; it will block until PATH_RESPONSE is injected.
      final rebindFuture = endpoint.rebindToAddress(conn, newAddr, newPort);

      // The probe packet was built with an empty DCID and 1-byte packet number,
      // so the PathChallengeFrame starts at byte offset 3.
      final probePacket = conn.lastProbePacket!;
      final challengeData = probePacket.sublist(3, 11);

      // Build a PATH_RESPONSE packet to complete validation.
      final responsePacket = PacketBuilder.build(
        ShortHeader(
          destinationConnectionId: [0, 0, 0, 0, 0, 0, 0, 0],
          packetNumber: 1,
          packetNumberLength: 1,
        ),
        [PathResponseFrame(data: challengeData)],
      );

      // Inject the response so the probe completes.
      conn.processIncomingDatagram(responsePacket);

      // Wait for rebind to finish.
      await rebindFuture;

      expect(endpoint.getRemoteAddress(conn)?.address, equals(newAddr.address));
      expect(endpoint.getRemotePort(conn), equals(newPort));

      endpoint.close();
    });
  });
}

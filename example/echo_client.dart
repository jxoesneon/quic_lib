import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/quic_lib.dart';

/// Minimal QUIC echo client example.
///
/// Demonstrates binding an endpoint, connecting to a server, opening a
/// bidirectional stream, and preparing a STREAM frame for sending.
/// Also demonstrates custom stream scheduling (ADR-006).
Future<void> main() async {
  // 1. Create a QuicEndpoint bound to an ephemeral port.
  final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
  print(
      'Endpoint bound to ${endpoint.localAddress.address}:${endpoint.localPort}');

  // 2. Connect to a server at 127.0.0.1:4433.
  final remoteAddress = InternetAddress.loopbackIPv4;
  const remotePort = 4433;

  try {
    final connection = await endpoint.connect(remoteAddress, remotePort);
    print('Connected: state=${connection.state}');

    // Demonstrates custom stream scheduling (ADR-006).
    connection.streamScheduler = RoundRobinScheduler();

    // 3. Open a bidirectional stream.
    final streamId = connection.openBidirectionalStream();
    print('Opened bidirectional stream $streamId');

    // 4. Prepare a simple message as a STREAM frame.
    final message = utf8.encode('Hello, QUIC!');
    final frame = StreamFrame(
      streamId: streamId,
      data: Uint8List.fromList(message),
      fin: true,
    );

    // 5. Build an Application-space packet containing the frame.
    final packet = await PacketSender.buildPacket(
      frames: [frame],
      space: PacketNumberSpace.application,
      dcid: [],
      packetNumber:
          connection.allocatePacketNumber(PacketNumberSpace.application),
    );

    print('Prepared packet with ${packet.length} bytes');
    print(
        'Client scaffold complete — full wire send path not yet wired end-to-end.');
  } finally {
    endpoint.close();
  }
}

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/quic_lib.dart';

/// Minimal QUIC echo client example.
///
/// Demonstrates binding an endpoint, connecting to a server, opening a
/// bidirectional stream, and writing data through the stream API. The raw
/// packet path is also shown for callers that need low-level control.
///
/// This example uses the public QUIC API to stage data; a real end-to-end
/// exchange requires the UDP send/recv path and TLS handshake to be wired.
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

    // 4. Write the message through the stream API.
    final message = Uint8List.fromList(utf8.encode('Hello, QUIC!'));
    final sendStream = connection.streamManager.getStream(streamId);
    if (sendStream is QuicSendStream) {
      sendStream.write(message);
      sendStream.close();
      print('Staged ${message.length} bytes on stream $streamId');
    } else {
      print('Could not obtain send stream for stream $streamId');
    }

    // 5. Alternatively, build an Application-space packet containing the frame.
    final frame = StreamFrame(
      streamId: streamId,
      data: message,
      fin: true,
    );
    final packet = await PacketSender.buildPacket(
      frames: [frame],
      space: PacketNumberSpace.application,
      dcid: [],
      packetNumber:
          connection.allocatePacketNumber(PacketNumberSpace.application),
    );
    print('Prepared packet with ${packet.length} bytes');

    print('Client scaffold complete — full wire send path not yet wired '
        'end-to-end.');
  } finally {
    endpoint.close();
  }
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:quic_lib/quic_lib.dart';

import 'echo_common.dart';

/// QUIC echo client over loopback.
///
/// Sends an encrypted STREAM frame containing [echoMessage] to
/// `127.0.0.1:12345` and waits for the server to echo it back. The client uses
/// deterministic application keys from [createEchoConnection] so the example
/// can run without a full TLS handshake.
///
/// Run with [echo_server.dart] listening first, then execute:
/// ```bash
/// dart run example/echo_client.dart
/// ```
Future<void> main() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  print('Client bound to ${socket.address.address}:${socket.port}');

  final connection = await createEchoConnection(role: EchoRole.client);
  connection.stateMachine
    ..transitionTo(ConnectionState.handshaking, reason: 'echo example')
    ..transitionTo(ConnectionState.established, reason: 'echo example');
  // Seed the anti-amplification budget so the first packet can be sent.
  connection.onBytesReceived(1000);

  // Pre-create the receive stream and listen so the echoed data is not lost
  // when the response datagram is processed synchronously.
  connection.streamManager.onStreamFrame(
    StreamFrame(streamId: 0, data: Uint8List(0), fin: false, offset: 0),
  );
  final receiveStream =
      connection.streamManager.getStream(0) as QuicReceiveStream;
  final receivedChunks = <Uint8List>[];
  receiveStream.incomingData.listen(receivedChunks.add);

  final completer = Completer<String>();
  final subscription = socket.listen((event) async {
    if (event != RawSocketEvent.read) return;
    final datagram = socket.receive();
    if (datagram == null) return;

    await connection.processEncryptedDatagram(datagram.data);

    while (receivedChunks.isNotEmpty) {
      final data = receivedChunks.removeAt(0);
      if (data.isEmpty) continue;
      completer.complete(utf8.decode(data));
    }
  });

  final message = Uint8List.fromList(utf8.encode(echoMessage));
  final packet = await connection.buildEncryptedPacket(
    space: PacketNumberSpace.application,
    frames: [
      StreamFrame(streamId: 0, data: message, fin: false, offset: 0),
    ],
    dcid: echoTestDcid,
  );

  socket.send(packet, InternetAddress.loopbackIPv4, echoServerPort);
  print('Sent: $echoMessage');

  try {
    final echoed = await completer.future.timeout(const Duration(seconds: 5));
    print('Received echo: $echoed');
  } on TimeoutException {
    print('Timed out waiting for echo. Is the server running?');
  }

  await subscription.cancel();
  socket.close();
  connection.abort();
}

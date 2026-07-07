import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:quic_lib/quic_lib.dart';

import 'echo_common.dart';

/// QUIC echo server over loopback.
///
/// Listens on `127.0.0.1:12345`, waits for a single encrypted STREAM frame,
/// and echoes the payload back to the sender on the same stream. The server
/// uses deterministic application keys from [createEchoConnection] so the
/// example can run without a full TLS handshake.
///
/// Run with:
/// ```bash
/// dart run example/echo_server.dart
/// ```
/// Then, in another terminal, run [echo_client.dart].
Future<void> main() async {
  final socket = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4, echoServerPort);
  print('QUIC echo server listening on '
      '${socket.address.address}:${socket.port}');

  final connection = await createEchoConnection(role: EchoRole.server);
  connection.stateMachine
    ..transitionTo(ConnectionState.handshaking, reason: 'echo example')
    ..transitionTo(ConnectionState.established, reason: 'echo example');

  // Pre-create the receive stream and listen so data is not lost when the
  // datagram is processed synchronously.
  connection.streamManager.onStreamFrame(
    StreamFrame(streamId: 0, data: Uint8List(0), fin: false, offset: 0),
  );
  final receiveStream =
      connection.streamManager.getStream(0) as QuicReceiveStream;
  final receivedChunks = <Uint8List>[];
  receiveStream.incomingData.listen(receivedChunks.add);

  InternetAddress? clientAddress;
  int? clientPort;

  final subscription = socket.listen((event) async {
    if (event != RawSocketEvent.read) return;
    final datagram = socket.receive();
    if (datagram == null) return;

    clientAddress = datagram.address;
    clientPort = datagram.port;

    // Yield so the synchronous RawDatagramSocket event dispatch completes
    // before we run the async QUIC packet processing.
    await Future.delayed(Duration.zero);
    await connection.processEncryptedDatagram(datagram.data);

    while (receivedChunks.isNotEmpty) {
      final data = receivedChunks.removeAt(0);
      if (data.isEmpty) continue;
      final text = utf8.decode(data);
      print('Received: $text');

      final echo = await connection.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(streamId: 0, data: data, fin: false, offset: 0),
        ],
        dcid: echoTestDcid,
      );

      if (clientAddress != null && clientPort != null) {
        socket.send(echo, clientAddress!, clientPort!);
        print('Echoed: $text');
      }
    }
  });

  print('Press Ctrl+C to stop.');
  await ProcessSignal.sigint.watch().first;

  await subscription.cancel();
  socket.close();
  connection.abort();
  print('Server stopped.');
}

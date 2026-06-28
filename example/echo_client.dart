import 'dart:io';

import 'package:quic_lib/dart_quic.dart';

/// Minimal QUIC echo client example.
///
/// This demonstrates the intended API usage pattern. The full connection
/// and stream API is not yet complete, so this example shows the scaffold.
Future<void> main() async {
  // 1. Create a QuicEndpoint bound to an ephemeral port.
  final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
  print(
      'Endpoint bound to ${endpoint.localAddress.address}:${endpoint.localPort}');

  // 2. Connect to a server at 127.0.0.1:4433.
  final remoteAddress = InternetAddress.loopbackIPv4;
  const remotePort = 4433;

  try {
    // TODO: Full connection establishment is not yet implemented.
    final connection = await endpoint.connect(remoteAddress, remotePort);
    print('Connected: $connection');

    // TODO: Stream API demonstration:
    // final streamId = connection.openBidirectionalStream();
    // connection.sendOnStream(streamId, utf8.encode('Hello, QUIC!'));
  } on UnimplementedError catch (e) {
    print('Expected unimplemented part: ${e.message}');
  } finally {
    endpoint.close();
  }
}

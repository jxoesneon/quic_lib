import 'dart:io';

import 'package:quic_lib/quic_lib.dart';

/// Minimal QUIC echo server example.
///
/// This demonstrates the intended API usage pattern. The full connection
/// and stream API is not yet complete, so this example shows the scaffold.
Future<void> main() async {
  // 1. Create a QuicEndpoint bound to 127.0.0.1:4433.
  final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 4433);
  print('QUIC echo server listening on '
      '${endpoint.localAddress.address}:${endpoint.localPort}');

  // 2. Handle graceful shutdown on Ctrl+C.
  ProcessSignal.sigint.watch().listen((_) {
    print('\nReceived shutdown signal, closing endpoint...');
    endpoint.close();
  });

  // 3. Listen for incoming connections.
  await for (final conn in endpoint.connections) {
    print('New connection: $conn');
    // TODO: Handle incoming streams once fully implemented.
  }

  print('Server stopped.');
}

import 'dart:io';
import 'dart:isolate';

import 'package:quic_lib/quic_lib.dart';

/// Minimal QUIC echo server example.
///
/// Demonstrates binding an endpoint, polling active connections,
/// registering each connection as an isolate (ADR-007), and listening for
/// incoming data on the receive side of each stream.
/// The full handshake-driven accept loop uses endpoint.connections
/// once wired end-to-end.
Future<void> main() async {
  // 1. Create a QuicEndpoint bound to 127.0.0.1:4433.
  final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 4433);
  print('QUIC echo server listening on '
      '${endpoint.localAddress.address}:${endpoint.localPort}');

  // 2. Handle graceful shutdown on Ctrl+C.
  var running = true;
  ProcessSignal.sigint.watch().listen((_) {
    print('\nReceived shutdown signal, closing endpoint...');
    running = false;
    endpoint.close();
  });

  // 3. Poll active connections and demonstrate isolate-per-connection.
  final registeredConnections = <QuicConnection>{};
  while (running) {
    await Future.delayed(const Duration(seconds: 1));
    for (final conn in endpoint.activeConnections) {
      if (!registeredConnections.contains(conn)) {
        registeredConnections.add(conn);
        final receivePort = ReceivePort();
        final isolate = ConnectionIsolate(
          connection: conn,
          sendPort: receivePort.sendPort,
          connectionId: 'conn-${conn.hashCode}',
        );
        isolate.start();
        endpoint.isolateSupervisor.register(isolate);
        print('Registered connection isolate. '
            'Active isolates: ${endpoint.isolateSupervisor.count}');
      }
      print('Active connection: state=${conn.state}');
      for (final stream in conn.streamManager.streams) {
        if (stream is QuicReceiveStream) {
          // Subscribe to incoming data on the receive side of the stream.
          stream.incomingData.listen((data) {
            print('  Stream ${stream.streamId} received ${data.length} bytes');
            // In a full implementation, the server would echo the data back.
            // For a bidirectional stream, that means writing to the matching
            // send stream; for a unidirectional stream, the response would be
            // sent on a new server-initiated unidirectional stream.
          });
        } else {
          print('  Stream ${stream.streamId} — echo scaffold would reply here');
        }
      }
    }
  }

  print('Server stopped.');
}

import 'dart:io';

import 'package:quic_lib/http3.dart';
import 'package:quic_lib/quic_lib.dart';

/// Minimal HTTP/3 client example.
///
/// Demonstrates wrapping a [QuicConnection] in an [Http3Connection],
/// exchanging SETTINGS, sending a request, and reading the staged response.
///
/// This example uses the public HTTP/3 API to stage frames; the actual
/// UDP send/recv path and TLS handshake must be wired for a real server.
Future<void> main() async {
  // 1. Bind a local endpoint and initiate a QUIC connection.
  final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
  print(
      'Endpoint bound to ${endpoint.localAddress.address}:${endpoint.localPort}');

  try {
    final connection = await endpoint.connect(
      InternetAddress.loopbackIPv4,
      4433,
    );
    print('Connected: state=${connection.state}');

    // 2. Wrap the QUIC connection in an HTTP/3 connection.
    final http3 = Http3Connection(quicConnection: connection);
    final settings = http3.sendSettings();
    print('Local HTTP/3 SETTINGS: '
        'maxFieldSectionSize=${settings.maxFieldSectionSize}, '
        'maxTableCapacity=${settings.maxTableCapacity}, '
        'blockedStreams=${settings.blockedStreams}');

    // 3. Build and send an HTTP/3 request on a new bidirectional stream.
    final request = Http3Request(
      method: 'GET',
      path: '/',
      headers: {
        'host': 'example.com',
        'user-agent': 'quic_lib',
      },
    );
    final streamId = await http3.sendRequest(request);
    print('Sent HTTP/3 request on stream $streamId');

    // 4. In a full implementation, the peer would send HEADERS/DATA frames
    //    on stream $streamId. Once the response frames arrive, read them with
    //    http3.getResponse(streamId) and any body with http3.getBody(streamId).
    print('Waiting for response frames on stream $streamId '
        '(requires handshake and UDP path to be wired).');

    // 5. Gracefully close the HTTP/3 connection and the endpoint.
    http3.close();
    print('HTTP/3 client scaffold complete.');
  } finally {
    endpoint.close();
  }
}

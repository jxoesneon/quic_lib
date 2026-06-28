import 'dart:io';

import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:test/test.dart';

void main() {
  group('QuicEndpoint.connect', () {
    late QuicEndpoint endpoint;

    setUp(() async {
      endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
    });

    tearDown(() {
      endpoint.close();
    });

    test('connect creates a QuicConnection in handshaking state', () async {
      final conn = await endpoint.connect(InternetAddress.loopbackIPv4, 12345);
      expect(conn, isA<QuicConnection>());
      expect(conn.state, equals(ConnectionState.handshaking));
    });

    test('connect adds connection to activeConnections', () async {
      expect(endpoint.activeConnections, isEmpty);
      await endpoint.connect(InternetAddress.loopbackIPv4, 12345);
      expect(endpoint.activeConnections, hasLength(1));
    });

    test('bind creates endpoint on ephemeral port', () async {
      expect(endpoint.localPort, greaterThan(0));
      expect(endpoint.localAddress, equals(InternetAddress.loopbackIPv4));
    });

    test('close disposes endpoint without error', () {
      expect(() => endpoint.close(), returnsNormally);
    });
  });
}

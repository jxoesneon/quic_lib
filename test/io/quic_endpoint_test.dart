import 'dart:io';

import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:test/test.dart';

void main() {
  group('QuicEndpoint', () {
    test('bind creates an endpoint', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      expect(endpoint.localPort, greaterThan(0));
      endpoint.close();
    });

    test('localAddress/localPort accessible', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      expect(
        endpoint.localAddress.address,
        equals(InternetAddress.loopbackIPv4.address),
      );
      expect(endpoint.localPort, greaterThan(0));
      endpoint.close();
    });

    test('close disposes resources', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      endpoint.close();

      await expectLater(endpoint.connections.toList(), completion(isEmpty));
    });
  });
}

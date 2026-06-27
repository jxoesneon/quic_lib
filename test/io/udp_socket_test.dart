import 'dart:io';
import 'dart:typed_data';

import 'package:dart_quic/src/io/udp_socket.dart';
import 'package:test/test.dart';

void main() {
  group('UdpSocket', () {
    test('bind creates a socket on a port', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      expect(socket.localPort, greaterThan(0));
      socket.close();
    });

    test('send/receive round-trip', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final received = socketB.incoming.first;
      final data = Uint8List.fromList([1, 2, 3, 4]);
      socketA.send(data, InternetAddress.loopbackIPv4, socketB.localPort);

      final datagram = await received;
      expect(datagram.data, equals(data));
      expect(
        datagram.address.address,
        equals(InternetAddress.loopbackIPv4.address),
      );
      expect(datagram.port, equals(socketA.localPort));

      socketA.close();
      socketB.close();
    });

    test('close stops the socket', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      socket.close();

      await expectLater(socket.incoming.toList(), completion(isEmpty));
    });
  });
}

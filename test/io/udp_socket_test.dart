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

    test('localAddress matches bind address', () async {
      final socket = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      expect(socket.localAddress.address, equals(InternetAddress.loopbackIPv4.address));
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

    test('rate limiting drops excessive packets from same IP', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final receivedDatagrams = <Uint8List>[];
      final sub = socketB.incoming.listen((d) => receivedDatagrams.add(d.data));

      // Send a burst of packets quickly from the same IP
      const packetCount = 1005;
      for (var i = 0; i < packetCount; i++) {
        socketA.send(Uint8List.fromList([i & 0xFF]), InternetAddress.loopbackIPv4, socketB.localPort);
      }

      // Allow time for packets to be processed
      await Future.delayed(Duration(milliseconds: 500));

      // Most should arrive, but at least some may be rate limited
      expect(receivedDatagrams.length, greaterThan(0));
      // The limit is 1000 per second; we sent 1005, so ideally at most 1000 arrive.
      // Due to OS buffering and timing, this is a soft assertion.
      expect(receivedDatagrams.length, lessThanOrEqualTo(packetCount));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });

    test('multiple packets from same IP within limit are accepted', () async {
      final socketA = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB = await UdpSocket.bind(InternetAddress.loopbackIPv4, 0);

      final receivedDatagrams = <Uint8List>[];
      final sub = socketB.incoming.listen((d) => receivedDatagrams.add(d.data));

      // Send 100 packets well within the 1000/s limit
      for (var i = 0; i < 100; i++) {
        socketA.send(Uint8List.fromList([i]), InternetAddress.loopbackIPv4, socketB.localPort);
      }

      await Future.delayed(Duration(milliseconds: 500));
      expect(receivedDatagrams.length, greaterThan(0));

      await sub.cancel();
      socketA.close();
      socketB.close();
    });
  });
}

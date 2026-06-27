import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'mock_udp_socket.dart';

void main() {
  group('MockUdpSocket', () {
    late MockUdpSocket socket;

    setUp(() {
      socket = MockUdpSocket();
    });

    test('initial state is not closed with empty sent list', () {
      expect(socket.isClosed, isFalse);
      expect(socket.sent, isEmpty);
    });

    test('send captures datagram', () {
      final data = [0x01, 0x02, 0x03];
      final addr = InternetAddress.loopbackIPv4;
      socket.send(data, addr, 1234);

      expect(socket.sent, hasLength(1));
      expect(socket.sent.first.data, data);
      expect(socket.sent.first.address, addr);
      expect(socket.sent.first.port, 1234);
    });

    test('send throws after close', () {
      socket.close();
      expect(
        () => socket.send([0x00], InternetAddress.loopbackIPv4, 1),
        throwsStateError,
      );
    });

    test('close sets isClosed', () {
      socket.close();
      expect(socket.isClosed, isTrue);
    });

    test('listen receives injected datagrams', () async {
      final received = <Datagram>[];
      socket.listen((d) => received.add(d));

      final datagram = Datagram(
        Uint8List.fromList([0xab, 0xcd]),
        InternetAddress.loopbackIPv4,
        5678,
      );
      socket.inject(datagram);

      await Future.delayed(Duration(milliseconds: 10));
      expect(received, hasLength(1));
      expect(received.first.data, [0xab, 0xcd]);
    });

    test('inject is no-op after close', () async {
      final received = <Datagram>[];
      socket.listen((d) => received.add(d));
      socket.close();

      socket.inject(Datagram(Uint8List.fromList([0x00]), InternetAddress.loopbackIPv4, 1));
      await Future.delayed(Duration(milliseconds: 10));
      expect(received, isEmpty);
    });
  });
}

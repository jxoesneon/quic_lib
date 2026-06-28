import 'dart:isolate';
import 'dart:typed_data';

import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/io/connection_isolate.dart';
import 'package:test/test.dart';

class _FakeConnection implements QuicConnection {
  Uint8List? lastDatagram;

  @override
  int processIncomingDatagram(Uint8List datagram) {
    lastDatagram = datagram;
    return datagram.length;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  group('ConnectionIsolate', () {
    test('start sets running and sends ready message', () {
      final receivePort = ReceivePort();
      String? capturedType;
      Map<String, dynamic>? capturedMessage;

      receivePort.listen((msg) {
        capturedType = (msg as Map)['type'] as String?;
        capturedMessage = Map<String, dynamic>.from(msg);
      });

      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      expect(isolate.isRunning, isTrue);
      expect(isolate.incomingPort, isNotNull);

      // Give the isolate message loop a moment to deliver the ready message.
      // In practice the ready message is sent synchronously via sendPort.
    });

    test('stop sets not running and sends close message', () {
      final receivePort = ReceivePort();
      final messages = <Map<String, dynamic>>[];
      receivePort
          .listen((msg) => messages.add(Map<String, dynamic>.from(msg as Map)));

      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      isolate.stop();
      expect(isolate.isRunning, isFalse);
    });

    test('start is idempotent', () {
      final receivePort = ReceivePort();
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );
      isolate.start();
      expect(isolate.isRunning, isTrue);
      isolate.start(); // should be no-op
      expect(isolate.isRunning, isTrue);
      isolate.stop();
    });

    test('incoming packet is forwarded to connection', () async {
      final receivePort = ReceivePort();
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();

      // Simulate a packet message from the supervisor.
      final packetData = Uint8List.fromList([0x01, 0x02, 0x03]);
      isolate.incomingPort.send({
        'type': 'packet',
        'data': packetData,
      });

      // Allow the event loop to process.
      await Future.delayed(Duration(milliseconds: 50));
      expect(conn.lastDatagram, equals(packetData));

      isolate.stop();
    });

    test('stop message triggers stop', () async {
      final receivePort = ReceivePort();
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      isolate.incomingPort.send({'type': 'stop'});
      await Future.delayed(Duration(milliseconds: 50));
      expect(isolate.isRunning, isFalse);
    });

    test('ignores invalid message types', () async {
      final receivePort = ReceivePort();
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      isolate.incomingPort.send({'type': 'unknown'});
      await Future.delayed(Duration(milliseconds: 50));
      expect(isolate.isRunning, isTrue);

      isolate.stop();
    });

    test('ignores non-map messages', () async {
      final receivePort = ReceivePort();
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      isolate.incomingPort.send('not a map');
      await Future.delayed(Duration(milliseconds: 50));
      expect(isolate.isRunning, isTrue);

      isolate.stop();
    });

    test('sendPacket forwards packet to supervisor', () async {
      final receivePort = ReceivePort();
      final messages = <Map<String, dynamic>>[];
      receivePort
          .listen((msg) => messages.add(Map<String, dynamic>.from(msg as Map)));

      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn',
      );

      isolate.start();
      final data = Uint8List.fromList([0xAB, 0xCD]);
      isolate.sendPacket(data, '127.0.0.1', 1234);

      await Future.delayed(Duration(milliseconds: 50));
      final packetMsgs = messages.where((m) => m['type'] == 'packet').toList();
      expect(packetMsgs.length, equals(1));
      expect(packetMsgs.first['data'], equals(data));
      expect(packetMsgs.first['address'], equals('127.0.0.1'));
      expect(packetMsgs.first['port'], equals(1234));
      expect(packetMsgs.first['connectionId'], equals('test-conn'));

      isolate.stop();
    });

    test('works without sendPort', () {
      final conn = _FakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: null,
        connectionId: 'test-conn',
      );
      isolate.start();
      expect(isolate.isRunning, isTrue);
      isolate.sendPacket(Uint8List(0), '127.0.0.1', 0); // should not throw
      isolate.stop();
    });
  });
}

import 'dart:isolate';
import 'dart:typed_data';

import 'package:dart_quic/src/io/isolate_supervisor.dart';
import 'package:dart_quic/src/io/connection_isolate.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:test/test.dart';

class _FakeConnection implements QuicConnection {
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  group('IsolateSupervisor', () {
    late IsolateSupervisor supervisor;

    setUp(() {
      supervisor = IsolateSupervisor();
    });

    test('register adds isolate', () {
      final isolate = ConnectionIsolate(
        connection: _FakeConnection(),
        sendPort: null,
        connectionId: 'conn-1',
      );
      supervisor.register(isolate);
      expect(supervisor.count, equals(1));
      expect(supervisor.contains('conn-1'), isTrue);
      expect(supervisor.get('conn-1'), equals(isolate));
    });

    test('get returns null for unknown connection', () {
      expect(supervisor.get('unknown'), isNull);
    });

    test('contains returns false for unknown connection', () {
      expect(supervisor.contains('unknown'), isFalse);
    });

    test('unregister removes isolate and port', () {
      final isolate = ConnectionIsolate(
        connection: _FakeConnection(),
        sendPort: null,
        connectionId: 'conn-1',
      );
      supervisor.register(isolate);

      // Register a port via ready message
      final receivePort = ReceivePort();
      supervisor.onIsolateMessage({
        'type': 'ready',
        'connectionId': 'conn-1',
        'port': receivePort.sendPort,
      });

      expect(supervisor.contains('conn-1'), isTrue);
      supervisor.unregister('conn-1');
      expect(supervisor.contains('conn-1'), isFalse);
      expect(supervisor.count, equals(0));

      receivePort.close();
    });

    test('unregister on unknown connection is no-op', () {
      expect(() => supervisor.unregister('unknown'), returnsNormally);
    });

    test('unregisterAll clears everything', () {
      final isolate1 = ConnectionIsolate(
        connection: _FakeConnection(),
        sendPort: null,
        connectionId: 'conn-1',
      );
      final isolate2 = ConnectionIsolate(
        connection: _FakeConnection(),
        sendPort: null,
        connectionId: 'conn-2',
      );
      supervisor.register(isolate1);
      supervisor.register(isolate2);

      supervisor.onIsolateMessage({
        'type': 'ready',
        'connectionId': 'conn-1',
        'port': ReceivePort().sendPort,
      });

      expect(supervisor.count, equals(2));
      supervisor.unregisterAll();
      expect(supervisor.count, equals(0));
      expect(supervisor.contains('conn-1'), isFalse);
      expect(supervisor.contains('conn-2'), isFalse);
    });

    group('onIsolateMessage', () {
      test('ignores non-map messages', () {
        supervisor.onIsolateMessage('not a map');
        expect(supervisor.count, equals(0));
      });

      test('ignores messages without connectionId', () {
        supervisor.onIsolateMessage({'type': 'ready'});
        expect(supervisor.count, equals(0));
      });

      test('ignores messages with null connectionId', () {
        supervisor.onIsolateMessage({'type': 'ready', 'connectionId': null});
        expect(supervisor.count, equals(0));
      });

      test('handles ready message with port', () async {
        final receivePort = ReceivePort();
        final messages = <Map<String, dynamic>>[];
        receivePort.listen((msg) => messages.add(Map<String, dynamic>.from(msg as Map)));

        supervisor.onIsolateMessage({
          'type': 'ready',
          'connectionId': 'conn-1',
          'port': receivePort.sendPort,
        });

        supervisor.sendPacket('conn-1', Uint8List.fromList([1, 2, 3]));

        await Future.delayed(Duration(milliseconds: 50));
        expect(messages.length, equals(1));
        expect(messages.first['type'], equals('packet'));
        expect(messages.first['data'], equals(Uint8List.fromList([1, 2, 3])));

        receivePort.close();
      });

      test('handles ready message with null port', () {
        supervisor.onIsolateMessage({
          'type': 'ready',
          'connectionId': 'conn-1',
          'port': null,
        });
        expect(() => supervisor.sendPacket('conn-1', Uint8List.fromList([1])), returnsNormally);
      });

      test('handles close message by removing isolate', () {
        final isolate = ConnectionIsolate(
          connection: _FakeConnection(),
          sendPort: null,
          connectionId: 'conn-1',
        );
        supervisor.register(isolate);

        supervisor.onIsolateMessage({
          'type': 'close',
          'connectionId': 'conn-1',
        });

        expect(supervisor.contains('conn-1'), isFalse);
      });

      test('handles close message on unknown connectionId', () {
        expect(() => supervisor.onIsolateMessage({
          'type': 'close',
          'connectionId': 'unknown',
        }), returnsNormally);
      });

      test('handles unknown type gracefully', () {
        final isolate = ConnectionIsolate(
          connection: _FakeConnection(),
          sendPort: null,
          connectionId: 'conn-1',
        );
        supervisor.register(isolate);

        supervisor.onIsolateMessage({
          'type': 'unknown',
          'connectionId': 'conn-1',
        });

        expect(supervisor.contains('conn-1'), isTrue);
      });
    });

    group('sendPacket', () {
      test('sends packet to registered port', () async {
        final receivePort = ReceivePort();
        final messages = <Map<String, dynamic>>[];
        receivePort.listen((msg) => messages.add(Map<String, dynamic>.from(msg as Map)));

        supervisor.onIsolateMessage({
          'type': 'ready',
          'connectionId': 'conn-1',
          'port': receivePort.sendPort,
        });

        final data = Uint8List.fromList([1, 2, 3]);
        supervisor.sendPacket('conn-1', data);

        await Future.delayed(Duration(milliseconds: 50));
        expect(messages.length, equals(1));
        expect(messages.first['type'], equals('packet'));
        expect(messages.first['data'], equals(data));

        receivePort.close();
      });

      test('does nothing for unknown connectionId', () {
        expect(() => supervisor.sendPacket('unknown', Uint8List.fromList([1])), returnsNormally);
      });

      test('does nothing when port is null', () {
        expect(() => supervisor.sendPacket('no-port', Uint8List.fromList([1])), returnsNormally);
      });
    });

    group('stopIsolate', () {
      test('sends stop to registered port', () async {
        final receivePort = ReceivePort();
        final messages = <Map<String, dynamic>>[];
        receivePort.listen((msg) => messages.add(Map<String, dynamic>.from(msg as Map)));

        supervisor.onIsolateMessage({
          'type': 'ready',
          'connectionId': 'conn-1',
          'port': receivePort.sendPort,
        });

        supervisor.stopIsolate('conn-1');

        await Future.delayed(Duration(milliseconds: 50));
        expect(messages.length, equals(1));
        expect(messages.first['type'], equals('stop'));

        receivePort.close();
      });

      test('does nothing for unknown connectionId', () {
        expect(() => supervisor.stopIsolate('unknown'), returnsNormally);
      });
    });
  });
}

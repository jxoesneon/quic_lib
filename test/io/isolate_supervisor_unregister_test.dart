import 'dart:isolate';

import 'package:dart_quic/dart_quic.dart';
import 'package:test/test.dart';

void main() {
  group('IsolateSupervisor.unregisterAll', () {
    test('clears all registered isolates', () {
      final supervisor = IsolateSupervisor();
      final isolate = ConnectionIsolate(
        connection: _FakeConnection(),
        sendPort: null,
        connectionId: 'test-1',
      );
      supervisor.register(isolate);
      expect(supervisor.count, equals(1));

      supervisor.unregisterAll();
      expect(supervisor.count, equals(0));
    });
  });
}

class _FakeConnection implements QuicConnection {
  @override dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

import 'package:quic_lib/src/connection/connection_registry.dart';
import 'package:test/test.dart';

void main() {
  group('ConnectionRegistry', () {
    late ConnectionRegistry registry;

    setUp(() {
      registry = ConnectionRegistry();
    });

    test('register/lookup round-trip', () {
      final cid = <int>[0x01, 0x02, 0x03, 0x04];
      final connection = Object();

      registry.register(cid, connection);
      final lookedUp = registry.lookup(cid);

      expect(lookedUp, same(connection));
    });

    test('unregister removes mapping', () {
      final cid = <int>[0xAB, 0xCD];
      final connection = Object();

      registry.register(cid, connection);
      expect(registry.lookup(cid), isNotNull);

      registry.unregister(cid);
      expect(registry.lookup(cid), isNull);
    });

    test('lookup returns null for unknown CID', () {
      final unknown = <int>[0xFF, 0xFF, 0xFF, 0xFF];
      expect(registry.lookup(unknown), isNull);
    });

    test('length tracking', () {
      expect(registry.length, equals(0));

      registry.register(<int>[0x01], Object());
      expect(registry.length, equals(1));

      registry.register(<int>[0x02], Object());
      expect(registry.length, equals(2));

      registry.unregister(<int>[0x01]);
      expect(registry.length, equals(1));

      registry.unregister(<int>[0x02]);
      expect(registry.length, equals(0));
    });

    test('register overwrites existing mapping', () {
      final cid = <int>[0xAA];
      final conn1 = Object();
      final conn2 = Object();

      registry.register(cid, conn1);
      expect(registry.lookup(cid), same(conn1));

      registry.register(cid, conn2);
      expect(registry.lookup(cid), same(conn2));
      expect(registry.length, equals(1));
    });
  });
}

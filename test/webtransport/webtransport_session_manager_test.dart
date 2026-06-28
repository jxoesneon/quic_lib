import 'package:dart_quic/src/webtransport/capsule_types.dart';
import 'package:dart_quic/src/webtransport/webtransport_session_manager.dart';
import 'package:test/test.dart';

void main() {
  group('WebTransportSessionManager', () {
    test('createSession returns a new session', () {
      final manager = WebTransportSessionManager();
      final session = manager.createSession(0);
      expect(session.sessionId, equals(0));
      expect(manager.sessionCount, equals(1));
    });

    test('createSession throws for duplicate streamId', () {
      final manager = WebTransportSessionManager();
      manager.createSession(0);
      expect(() => manager.createSession(0), throwsStateError);
    });

    test('getSession returns existing session', () {
      final manager = WebTransportSessionManager();
      final created = manager.createSession(4);
      final retrieved = manager.getSession(4);
      expect(retrieved, same(created));
    });

    test('getSession returns null for unknown streamId', () {
      final manager = WebTransportSessionManager();
      expect(manager.getSession(99), isNull);
    });

    test('routeCapsule creates session if needed', () {
      final manager = WebTransportSessionManager();
      final capsule = Capsule(
        type: CapsuleType.datagram,
        payload: [0x01, 0x02],
      );
      manager.routeCapsule(8, capsule);
      expect(manager.sessionCount, equals(1));
      final session = manager.getSession(8)!;
      expect(session.receivedDatagrams.length, equals(1));
    });

    test('removeSession deletes the session', () {
      final manager = WebTransportSessionManager();
      manager.createSession(0);
      manager.removeSession(0);
      expect(manager.sessionCount, equals(0));
    });

    test('cleanupInactiveSessions removes closed sessions', () {
      final manager = WebTransportSessionManager();
      final active = manager.createSession(0);
      final closing = manager.createSession(4);
      closing.onCapsuleReceived(
        Capsule(type: CapsuleType.closeWebTransportSession, payload: []),
      );
      expect(manager.cleanupInactiveSessions(), equals(1));
      expect(manager.sessionCount, equals(1));
      expect(manager.getSession(0), same(active));
    });

    test('closeAll clears all sessions', () {
      final manager = WebTransportSessionManager();
      manager.createSession(0);
      manager.createSession(4);
      manager.closeAll();
      expect(manager.sessionCount, equals(0));
    });
  });
}

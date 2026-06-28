import 'package:test/test.dart';
import 'package:quic_lib/src/webtransport/capsule_router.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';

void main() {
  group('CapsuleRouter', () {
    late CapsuleRouter router;

    setUp(() {
      router = CapsuleRouter();
    });

    test('routeCapsule creates session when none exists', () {
      const streamId = 4;
      expect(router.getSession(streamId), isNull);

      router.routeCapsule(
        streamId,
        Capsule(type: CapsuleType.grease0, payload: [0x01]),
      );

      final session = router.getSession(streamId);
      expect(session, isNotNull);
      expect(session!.sessionId, equals(streamId));
      expect(session.isActive, isTrue);
    });

    test('routeCapsule forwards capsule to existing session', () {
      const streamId = 8;
      router.routeCapsule(
        streamId,
        Capsule(type: CapsuleType.grease0, payload: [0x01]),
      );

      router.routeCapsule(
        streamId,
        Capsule(type: CapsuleType.closeWebTransportSession, payload: []),
      );

      final session = router.getSession(streamId);
      expect(session, isNotNull);
      expect(session!.isClosed, isTrue);
    });

    test('getSession returns null for unknown streamId', () {
      expect(router.getSession(99), isNull);
    });

    test('closeSession removes the session', () {
      const streamId = 12;
      router.routeCapsule(
        streamId,
        Capsule(type: CapsuleType.grease1, payload: [0x02]),
      );
      expect(router.getSession(streamId), isNotNull);

      router.closeSession(streamId);
      expect(router.getSession(streamId), isNull);
    });

    test('multiple sessions are tracked independently', () {
      const streamIdA = 0;
      const streamIdB = 4;

      router.routeCapsule(
        streamIdA,
        Capsule(type: CapsuleType.closeWebTransportSession, payload: []),
      );
      router.routeCapsule(
        streamIdB,
        Capsule(type: CapsuleType.drainWebTransportSession, payload: []),
      );

      final sessionA = router.getSession(streamIdA);
      final sessionB = router.getSession(streamIdB);

      expect(sessionA!.isClosed, isTrue);
      expect(sessionB!.isDraining, isTrue);
    });
  });
}

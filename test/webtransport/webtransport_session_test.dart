import 'package:test/test.dart';
import 'package:dart_quic/src/webtransport/webtransport_session.dart';
import 'package:dart_quic/src/webtransport/capsule_types.dart';

void main() {
  group('WebTransportSession', () {
    test('starts active', () {
      final session = WebTransportSession(1);
      expect(session.isActive, isTrue);
      expect(session.isDraining, isFalse);
      expect(session.isClosed, isFalse);
    });

    test('onCapsuleReceived(CLOSE) marks closed', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: [],
      ));
      expect(session.isClosed, isTrue);
      expect(session.isActive, isFalse);
    });

    test('onCapsuleReceived(DRAIN) marks draining', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.drainWebTransportSession,
        payload: [],
      ));
      expect(session.isDraining, isTrue);
      expect(session.isActive, isFalse);
    });

    test('initiateClose returns correct capsule type', () {
      final session = WebTransportSession(1);
      final capsule = session.initiateClose(errorCode: 42);
      expect(capsule.type, equals(CapsuleType.closeWebTransportSession));
    });

    test('initiateDrain returns correct capsule type', () {
      final session = WebTransportSession(1);
      final capsule = session.initiateDrain();
      expect(capsule.type, equals(CapsuleType.drainWebTransportSession));
    });

    test('onCloseAcknowledged after close', () {
      final session = WebTransportSession(1);
      session.initiateClose();
      session.onCloseAcknowledged();
      expect(session.isClosed, isTrue);
    });

    test('unknown capsule is ignored', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.grease0,
        payload: [0x01],
      ));
      expect(session.isActive, isTrue);
    });
  });
}

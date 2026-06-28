import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';

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

    test('sessionId getter', () {
      final session = WebTransportSession(42);
      expect(session.sessionId, equals(42));
    });

    test('initiateClose with reasonPhrase', () {
      final session = WebTransportSession(1);
      final capsule = session.initiateClose(errorCode: 1, reasonPhrase: 'test');
      expect(capsule.type, equals(CapsuleType.closeWebTransportSession));
      expect(capsule.payload, isNotEmpty);
    });

    test('sendDatagram returns datagram capsule', () {
      final session = WebTransportSession(1);
      final data = Uint8List.fromList([0x01, 0x02, 0x03]);
      final capsule = session.sendDatagram(data);
      expect(capsule.type, equals(CapsuleType.datagram));
      expect(capsule.payload, equals(data));
    });

    test('sendGoaway without streamId', () {
      final session = WebTransportSession(1);
      final goaway = session.sendGoaway();
      expect(goaway.streamId, isNull);
    });

    test('sendGoaway with streamId', () {
      final session = WebTransportSession(1);
      final goaway = session.sendGoaway(streamId: 10);
      expect(goaway.streamId, equals(10));
    });

    test('onCapsuleReceived(DATAGRAM) stores datagram', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.datagram,
        payload: [0xAA, 0xBB],
      ));
      expect(session.receivedDatagrams.length, equals(1));
      expect(session.receivedDatagrams.first, equals([0xAA, 0xBB]));
    });

    test('onCapsuleReceived(REGISTER_BIDIRECTIONAL_STREAM)', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.registerBidirectionalStream,
        payload: [0x08],
      ));
      expect(session.registeredBidirectionalStreams, contains(8));
    });

    test('onCapsuleReceived(REGISTER_UNIDIRECTIONAL_STREAM)', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.registerUnidirectionalStream,
        payload: [0x0C],
      ));
      expect(session.registeredUnidirectionalStreams, contains(12));
    });

    test('onCapsuleReceived(GOAWAY) sets receivedGoaway', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.goaway,
        payload: [],
      ));
      expect(session.receivedGoaway, isTrue);
    });
  });
}

import 'package:test/test.dart';
import 'package:quic_lib/src/libp2p/dcutr_state_machine.dart';

void main() {
  group('DCUtRStateMachine', () {
    late DCUtRStateMachine sm;

    setUp(() {
      sm = DCUtRStateMachine();
    });

    test('initial state is idle', () {
      expect(sm.state, equals(DCUtRState.idle));
      expect(sm.isConnected, isFalse);
    });

    test('onConnectSent transitions idle -> connectSent', () {
      sm.onConnectSent();
      expect(sm.state, equals(DCUtRState.connectSent));
      expect(sm.isConnected, isFalse);
    });

    test('onSyncReceived transitions connectSent -> syncReceived', () {
      sm.onConnectSent();
      sm.onSyncReceived();
      expect(sm.state, equals(DCUtRState.syncReceived));
      expect(sm.isConnected, isFalse);
    });

    test('second onSyncReceived transitions syncReceived -> connected', () {
      sm.onConnectSent();
      sm.onSyncReceived();
      sm.onSyncReceived();
      expect(sm.state, equals(DCUtRState.connected));
      expect(sm.isConnected, isTrue);
    });

    test('onConnectReceived transitions idle -> connected (listener)', () {
      sm.onConnectReceived();
      expect(sm.state, equals(DCUtRState.connected));
      expect(sm.isConnected, isTrue);
    });

    test('onTimeout transitions idle -> failed', () {
      sm.onTimeout();
      expect(sm.state, equals(DCUtRState.failed));
      expect(sm.isConnected, isFalse);
    });

    test('onTimeout transitions connectSent -> failed', () {
      sm.onConnectSent();
      sm.onTimeout();
      expect(sm.state, equals(DCUtRState.failed));
      expect(sm.isConnected, isFalse);
    });

    test('onTimeout transitions syncReceived -> failed', () {
      sm.onConnectSent();
      sm.onSyncReceived();
      sm.onTimeout();
      expect(sm.state, equals(DCUtRState.failed));
      expect(sm.isConnected, isFalse);
    });

    test('onTimeout transitions connected -> failed', () {
      sm.onConnectReceived();
      sm.onTimeout();
      expect(sm.state, equals(DCUtRState.failed));
      expect(sm.isConnected, isFalse);
    });

    test('onConnectSent is ignored when not idle', () {
      sm.onConnectReceived(); // idle -> connected
      sm.onConnectSent();
      expect(sm.state, equals(DCUtRState.connected));
    });

    test('onConnectReceived is ignored when not idle', () {
      sm.onConnectSent(); // idle -> connectSent
      sm.onConnectReceived();
      expect(sm.state, equals(DCUtRState.connectSent));
    });

    test('onSyncReceived is ignored in idle', () {
      sm.onSyncReceived();
      expect(sm.state, equals(DCUtRState.idle));
    });

    test('onSyncReceived is ignored in connected', () {
      sm.onConnectReceived(); // idle -> connected
      sm.onSyncReceived();
      expect(sm.state, equals(DCUtRState.connected));
    });

    test('onSyncReceived is ignored in failed', () {
      sm.onConnectSent();
      sm.onTimeout(); // -> failed
      sm.onSyncReceived();
      expect(sm.state, equals(DCUtRState.failed));
    });
  });
}

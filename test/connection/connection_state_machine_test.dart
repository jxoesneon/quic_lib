import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:test/test.dart';

void main() {
  group('ConnectionStateMachine', () {
    late ConnectionStateMachine sm;

    setUp(() {
      sm = ConnectionStateMachine();
    });

    tearDown(() {
      sm.dispose();
    });

    test('initial state is idle', () {
      expect(sm.state, ConnectionState.idle);
      expect(sm.isIdle, isTrue);
      expect(sm.isHandshaking, isFalse);
      expect(sm.isEstablished, isFalse);
      expect(sm.isClosing, isFalse);
      expect(sm.isClosed, isFalse);
      expect(sm.isDraining, isFalse);
    });

    test('idle → handshaking → established', () {
      sm.transitionTo(ConnectionState.handshaking, reason: 'connect');
      expect(sm.state, ConnectionState.handshaking);
      expect(sm.isHandshaking, isTrue);

      sm.transitionTo(ConnectionState.established,
          reason: 'handshake complete');
      expect(sm.state, ConnectionState.established);
      expect(sm.isEstablished, isTrue);
    });

    test('established → closing → closed', () {
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);

      sm.transitionTo(ConnectionState.closing, reason: 'close initiated');
      expect(sm.state, ConnectionState.closing);
      expect(sm.isClosing, isTrue);

      sm.transitionTo(ConnectionState.closed, reason: 'close timeout');
      expect(sm.state, ConnectionState.closed);
      expect(sm.isClosed, isTrue);
    });

    test('established → draining → closed', () {
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);

      sm.transitionTo(ConnectionState.draining,
          reason: 'CONNECTION_CLOSE received');
      expect(sm.state, ConnectionState.draining);
      expect(sm.isDraining, isTrue);

      sm.transitionTo(ConnectionState.closed, reason: 'drain timeout');
      expect(sm.state, ConnectionState.closed);
      expect(sm.isClosed, isTrue);
    });

    test('invalid transitions throw StateError', () {
      // idle → established directly
      expect(
        () => sm.transitionTo(ConnectionState.established),
        throwsA(isA<StateError>()),
      );

      // idle → closing
      expect(
        () => sm.transitionTo(ConnectionState.closing),
        throwsA(isA<StateError>()),
      );

      // handshaking → draining
      sm.transitionTo(ConnectionState.handshaking);
      expect(
        () => sm.transitionTo(ConnectionState.draining),
        throwsA(isA<StateError>()),
      );

      // closed is terminal
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.closing);
      sm.transitionTo(ConnectionState.closed);
      expect(
        () => sm.transitionTo(ConnectionState.idle),
        throwsA(isA<StateError>()),
      );
    });

    test('state change stream emits correct sequence', () async {
      final states = <ConnectionState>[];
      final subscription = sm.onStateChanged.listen(states.add);

      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.closing);
      sm.transitionTo(ConnectionState.closed);

      // Allow microtask queue to drain.
      await Future.delayed(Duration.zero);

      expect(states, [
        ConnectionState.handshaking,
        ConnectionState.established,
        ConnectionState.closing,
        ConnectionState.closed,
      ]);

      await subscription.cancel();
    });

    test('canSendData per state', () {
      expect(sm.canSendData, isFalse); // idle

      sm.transitionTo(ConnectionState.handshaking);
      expect(sm.canSendData, isFalse);

      sm.transitionTo(ConnectionState.established);
      expect(sm.canSendData, isTrue);

      sm.transitionTo(ConnectionState.closing);
      expect(sm.canSendData, isTrue);

      sm.transitionTo(ConnectionState.closed);
      expect(sm.canSendData, isFalse);

      // Drain path
      sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.draining);
      expect(sm.canSendData, isFalse);
    });

    test('canReceiveData per state', () {
      expect(sm.canReceiveData, isFalse); // idle

      sm.transitionTo(ConnectionState.handshaking);
      expect(sm.canReceiveData, isTrue);

      sm.transitionTo(ConnectionState.established);
      expect(sm.canReceiveData, isTrue);

      sm.transitionTo(ConnectionState.closing);
      expect(sm.canReceiveData, isFalse);

      sm.transitionTo(ConnectionState.closed);
      expect(sm.canReceiveData, isFalse);

      // Drain path
      sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      sm.transitionTo(ConnectionState.draining);
      expect(sm.canReceiveData, isFalse);
    });
  });
}

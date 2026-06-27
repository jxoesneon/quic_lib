import 'package:dart_quic/src/streams/send_state_machine.dart';
import 'package:test/test.dart';

void main() {
  group('SendStateMachine', () {
    test('initial state is ready', () {
      final sm = SendStateMachine();
      expect(sm.state, SendStreamState.ready);
      expect(sm.isTerminal, isFalse);
      expect(sm.canSend, isTrue);
      expect(sm.wasReset, isFalse);
    });

    test('ready → send → sent → received', () {
      final sm = SendStateMachine();
      sm.onDataSent();
      expect(sm.state, SendStreamState.send);
      expect(sm.canSend, isTrue);
      expect(sm.isTerminal, isFalse);
      expect(sm.wasReset, isFalse);

      sm.onFinSent();
      expect(sm.state, SendStreamState.sent);
      expect(sm.canSend, isFalse);
      expect(sm.isTerminal, isFalse);
      expect(sm.wasReset, isFalse);

      sm.onAllDataAcked();
      expect(sm.state, SendStreamState.received);
      expect(sm.isTerminal, isTrue);
      expect(sm.canSend, isFalse);
      expect(sm.wasReset, isFalse);
    });

    test('ready → send → resetSent → resetReceived', () {
      final sm = SendStateMachine();
      sm.onDataSent();
      expect(sm.state, SendStreamState.send);

      sm.onResetSent();
      expect(sm.state, SendStreamState.resetSent);
      expect(sm.wasReset, isTrue);
      expect(sm.canSend, isFalse);
      expect(sm.isTerminal, isFalse);

      sm.onResetAcked();
      expect(sm.state, SendStreamState.resetReceived);
      expect(sm.isTerminal, isTrue);
      expect(sm.wasReset, isTrue);
    });

    test('send → resetSent (abort via onStopSendingReceived)', () {
      final sm = SendStateMachine();
      sm.onDataSent();
      expect(sm.state, SendStreamState.send);

      sm.onStopSendingReceived();
      expect(sm.state, SendStreamState.resetSent);
      expect(sm.wasReset, isTrue);
      expect(sm.canSend, isFalse);
    });

    test('ready → resetSent directly', () {
      final sm = SendStateMachine();
      sm.onResetSent();
      expect(sm.state, SendStreamState.resetSent);
      expect(sm.wasReset, isTrue);
      expect(sm.canSend, isFalse);
      expect(sm.isTerminal, isFalse);
    });

    test('sent → resetSent is valid', () {
      final sm = SendStateMachine();
      sm.onDataSent();
      sm.onFinSent();
      expect(sm.state, SendStreamState.sent);

      sm.onResetSent();
      expect(sm.state, SendStreamState.resetSent);
      expect(sm.wasReset, isTrue);
    });

    test('sent → resetSent via onStopSendingReceived', () {
      final sm = SendStateMachine();
      sm.onDataSent();
      sm.onFinSent();
      expect(sm.state, SendStreamState.sent);

      sm.onStopSendingReceived();
      expect(sm.state, SendStreamState.resetSent);
    });

    test('invalid transitions throw StateError', () {
      final sm = SendStateMachine();

      // ready → sent (invalid)
      expect(() => sm.transitionTo(SendStreamState.sent), throwsStateError);
      // ready → received (invalid)
      expect(
          () => sm.transitionTo(SendStreamState.received), throwsStateError);
      // ready → resetReceived (invalid)
      expect(() => sm.transitionTo(SendStreamState.resetReceived),
          throwsStateError);

      sm.onDataSent();
      // send → received (invalid)
      expect(
          () => sm.transitionTo(SendStreamState.received), throwsStateError);
      // send → ready (invalid)
      expect(() => sm.transitionTo(SendStreamState.ready), throwsStateError);

      sm.onFinSent();
      // sent → send (invalid)
      expect(() => sm.transitionTo(SendStreamState.send), throwsStateError);
      // sent → ready (invalid)
      expect(() => sm.transitionTo(SendStreamState.ready), throwsStateError);

      sm.onAllDataAcked();
      // received → any (terminal)
      expect(() => sm.transitionTo(SendStreamState.send), throwsStateError);
      expect(() => sm.transitionTo(SendStreamState.sent), throwsStateError);
      expect(
          () => sm.transitionTo(SendStreamState.resetSent), throwsStateError);
      expect(() => sm.transitionTo(SendStreamState.resetReceived),
          throwsStateError);
      expect(() => sm.transitionTo(SendStreamState.ready), throwsStateError);

      final sm2 = SendStateMachine();
      sm2.onResetSent();
      // resetSent → ready/send/sent/received (invalid)
      expect(() => sm2.transitionTo(SendStreamState.ready), throwsStateError);
      expect(() => sm2.transitionTo(SendStreamState.send), throwsStateError);
      expect(() => sm2.transitionTo(SendStreamState.sent), throwsStateError);
      expect(
          () => sm2.transitionTo(SendStreamState.received), throwsStateError);

      sm2.onResetAcked();
      // resetReceived → any (terminal)
      expect(() => sm2.transitionTo(SendStreamState.ready), throwsStateError);
      expect(() => sm2.transitionTo(SendStreamState.send), throwsStateError);
      expect(() => sm2.transitionTo(SendStreamState.sent), throwsStateError);
      expect(
          () => sm2.transitionTo(SendStreamState.received), throwsStateError);
      expect(() => sm2.transitionTo(SendStreamState.resetSent), throwsStateError);
    });

    test('isTerminal, canSend, wasReset flags across states', () {
      final sm = SendStateMachine();
      expect(sm.isTerminal, isFalse);
      expect(sm.canSend, isTrue);
      expect(sm.wasReset, isFalse);

      sm.onDataSent();
      expect(sm.isTerminal, isFalse);
      expect(sm.canSend, isTrue);
      expect(sm.wasReset, isFalse);

      sm.onFinSent();
      expect(sm.isTerminal, isFalse);
      expect(sm.canSend, isFalse);
      expect(sm.wasReset, isFalse);

      sm.onAllDataAcked();
      expect(sm.isTerminal, isTrue);
      expect(sm.canSend, isFalse);
      expect(sm.wasReset, isFalse);

      final sm2 = SendStateMachine();
      sm2.onResetSent();
      expect(sm2.isTerminal, isFalse);
      expect(sm2.canSend, isFalse);
      expect(sm2.wasReset, isTrue);

      sm2.onResetAcked();
      expect(sm2.isTerminal, isTrue);
      expect(sm2.canSend, isFalse);
      expect(sm2.wasReset, isTrue);
    });
  });
}

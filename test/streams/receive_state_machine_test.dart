import 'package:test/test.dart';
import 'package:dart_quic/src/streams/receive_state_machine.dart';

void main() {
  group('ReceiveStateMachine', () {
    test('initial state is recv', () {
      final sm = ReceiveStateMachine();
      expect(sm.state, equals(ReceiveStreamState.recv));
      expect(sm.isTerminal, isFalse);
      expect(sm.canReceive, isTrue);
    });

    test('recv → dataReceived → dataRead', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived();
      sm.onAllDataReceived();
      expect(sm.state, equals(ReceiveStreamState.dataReceived));
      sm.onDataRead();
      expect(sm.state, equals(ReceiveStreamState.dataRead));
      expect(sm.isTerminal, isTrue);
    });

    test('recv → resetReceived → resetRead', () {
      final sm = ReceiveStateMachine();
      sm.onResetReceived();
      expect(sm.state, equals(ReceiveStreamState.resetReceived));
      sm.onResetRead();
      expect(sm.state, equals(ReceiveStreamState.resetRead));
      expect(sm.isTerminal, isTrue);
      expect(sm.wasReset, isTrue);
    });

    test('FIN sets final size', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100);
      expect(sm.finalSize, equals(100));
    });

    test('inconsistent final size throws', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100);
      expect(() => sm.onDataReceived(fin: true, finalSize: 200), throwsStateError);
    });

    test('bytesReceived exceeding finalSize throws', () {
      final sm = ReceiveStateMachine();
      expect(
        () => sm.onDataReceived(fin: true, finalSize: 50, bytesReceived: 100),
        throwsStateError,
      );
    });

    test('bytesReceived within finalSize is accepted', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100, bytesReceived: 50);
      expect(sm.finalSize, equals(100));
      expect(sm.bytesReceived, equals(50));
    });

    test('canReceive when sizeKnown', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100);
      expect(sm.canReceive, isTrue);
    });

    test('bytesReceived exceeding previously set finalSize throws', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100, bytesReceived: 50);
      // Later receive more data than finalSize allows.
      expect(
        () => sm.onDataReceived(bytesReceived: 150),
        throwsStateError,
      );
    });

    test('onResetReceived from sizeKnown', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived(fin: true, finalSize: 100);
      sm.onResetReceived();
      expect(sm.state, equals(ReceiveStreamState.resetReceived));
    });

    test('onResetReceived from dataReceived', () {
      final sm = ReceiveStateMachine();
      sm.onDataReceived();
      sm.onAllDataReceived();
      sm.onResetReceived();
      expect(sm.state, equals(ReceiveStreamState.resetReceived));
    });
  });
}

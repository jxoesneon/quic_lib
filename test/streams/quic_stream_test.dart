import 'dart:typed_data';

import 'package:dart_quic/src/streams/quic_stream.dart';
import 'package:dart_quic/src/streams/send_state_machine.dart';
import 'package:dart_quic/src/streams/receive_state_machine.dart';
import 'package:test/test.dart';

void main() {
  group('QuicSendStream', () {
    test('writes data and emits on outgoingData', () async {
      final sm = SendStateMachine();
      final stream = QuicSendStream(0, stateMachine: sm);

      final emitted = <Uint8List>[];
      stream.outgoingData.listen(emitted.add);

      final data = Uint8List.fromList([1, 2, 3]);
      stream.write(data);

      await Future.delayed(Duration.zero);

      expect(emitted.length, equals(1));
      expect(emitted.first, equals(data));
      expect(sm.state, equals(SendStreamState.send));
    });

    test('close triggers FIN and completes done', () async {
      final sm = SendStateMachine();
      final stream = QuicSendStream(0, stateMachine: sm);

      final emitted = <Uint8List>[];
      stream.outgoingData.listen(emitted.add);

      stream.close();

      await expectLater(stream.done, completes);
      expect(sm.state, equals(SendStreamState.sent));
    });

    test('reset transitions state machine', () {
      final sm = SendStateMachine();
      final stream = QuicSendStream(0, stateMachine: sm);

      stream.reset();

      expect(sm.state, equals(SendStreamState.resetSent));
    });
  });

  group('QuicReceiveStream', () {
    test('delivers data and emits on incomingData', () async {
      final sm = ReceiveStateMachine();
      final stream = QuicReceiveStream(2, stateMachine: sm);

      final emitted = <Uint8List>[];
      stream.incomingData.listen(emitted.add);

      final data = Uint8List.fromList([4, 5, 6]);
      stream.deliver(data);

      await Future.delayed(Duration.zero);

      expect(emitted.length, equals(1));
      expect(emitted.first, equals(data));
      expect(sm.state, equals(ReceiveStreamState.recv));
    });

    test('deliver with fin closes stream and transitions state', () async {
      final sm = ReceiveStateMachine();
      final stream = QuicReceiveStream(2, stateMachine: sm);

      final emitted = <Uint8List>[];
      stream.incomingData.listen(emitted.add);

      final data = Uint8List.fromList([7, 8, 9]);
      stream.deliver(data, fin: true);

      await expectLater(stream.done, completes);
      expect(emitted.length, equals(1));
      expect(sm.state, equals(ReceiveStreamState.dataReceived));
    });

    test('write throws UnsupportedError', () {
      final sm = ReceiveStateMachine();
      final stream = QuicReceiveStream(2, stateMachine: sm);

      expect(() => stream.write(Uint8List(0)), throwsUnsupportedError);
    });

    test('reset transitions state machine', () {
      final sm = ReceiveStateMachine();
      final stream = QuicReceiveStream(2, stateMachine: sm);

      stream.reset();

      expect(sm.state, equals(ReceiveStreamState.resetReceived));
    });
  });

  group('Stream ID type detection', () {
    test('bidirectional stream IDs', () {
      final sendSm = SendStateMachine();
      final recvSm = ReceiveStateMachine();

      final sendStream = QuicSendStream(0, stateMachine: sendSm);
      final recvStream = QuicReceiveStream(1, stateMachine: recvSm);

      expect(sendStream.isBidirectional, isTrue);
      expect(sendStream.isUnidirectional, isFalse);
      expect(recvStream.isBidirectional, isTrue);
      expect(recvStream.isUnidirectional, isFalse);
    });

    test('unidirectional stream IDs', () {
      final sendSm = SendStateMachine();
      final recvSm = ReceiveStateMachine();

      final sendStream = QuicSendStream(2, stateMachine: sendSm);
      final recvStream = QuicReceiveStream(3, stateMachine: recvSm);

      expect(sendStream.isBidirectional, isFalse);
      expect(sendStream.isUnidirectional, isTrue);
      expect(recvStream.isBidirectional, isFalse);
      expect(recvStream.isUnidirectional, isTrue);
    });

    test('various stream IDs', () {
      final sm = SendStateMachine();

      expect(QuicSendStream(0x00, stateMachine: sm).isBidirectional, isTrue);
      expect(QuicSendStream(0x01, stateMachine: sm).isBidirectional, isTrue);
      expect(QuicSendStream(0x02, stateMachine: sm).isUnidirectional, isTrue);
      expect(QuicSendStream(0x03, stateMachine: sm).isUnidirectional, isTrue);
      expect(QuicSendStream(0x04, stateMachine: sm).isBidirectional, isTrue);
      expect(QuicSendStream(0x06, stateMachine: sm).isUnidirectional, isTrue);
      expect(QuicSendStream(0x0A, stateMachine: sm).isUnidirectional, isTrue);
      expect(QuicSendStream(0x10, stateMachine: sm).isBidirectional, isTrue);
    });
  });
}

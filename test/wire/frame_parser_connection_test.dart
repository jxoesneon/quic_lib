import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('Connection-management frame parsing', () {
    test('parse NEW_CONNECTION_ID', () {
      final original = NewConnectionIdFrame(
        sequenceNumber: 42,
        retirePriorTo: 7,
        connectionId: [0x01, 0x02, 0x03],
        statelessResetToken: List<int>.filled(16, 0xAB),
      );
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<NewConnectionIdFrame>());
      final p = parsed as NewConnectionIdFrame;
      expect(p.sequenceNumber, equals(42));
      expect(p.retirePriorTo, equals(7));
      expect(p.connectionId, equals([0x01, 0x02, 0x03]));
      expect(p.statelessResetToken, equals(List<int>.filled(16, 0xAB)));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse RETIRE_CONNECTION_ID', () {
      final original = RetireConnectionIdFrame(sequenceNumber: 99);
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<RetireConnectionIdFrame>());
      expect((parsed as RetireConnectionIdFrame).sequenceNumber, equals(99));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse PATH_CHALLENGE', () {
      final original = PathChallengeFrame(data: List<int>.filled(8, 0xCD));
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<PathChallengeFrame>());
      expect((parsed as PathChallengeFrame).data,
          equals(List<int>.filled(8, 0xCD)));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse PATH_RESPONSE', () {
      final original = PathResponseFrame(data: List<int>.filled(8, 0xEF));
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<PathResponseFrame>());
      expect((parsed as PathResponseFrame).data,
          equals(List<int>.filled(8, 0xEF)));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse CONNECTION_CLOSE transport', () {
      final original = ConnectionCloseFrame(
        errorCode: 0x0100,
        offendingFrameType: 0x06,
        reasonPhrase: 'test',
      );
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<ConnectionCloseFrame>());
      final p = parsed as ConnectionCloseFrame;
      expect(p.errorCode, equals(0x0100));
      expect(p.offendingFrameType, equals(0x06));
      expect(p.reasonPhrase, equals('test'));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse APPLICATION_CLOSE', () {
      final original =
          ApplicationCloseFrame(errorCode: 0x0200, reasonPhrase: 'done');
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<ApplicationCloseFrame>());
      final p = parsed as ApplicationCloseFrame;
      expect(p.errorCode, equals(0x0200));
      expect(p.reasonPhrase, equals('done'));
      expect(nextOffset, equals(bytes.length));
    });

    test('parse HANDSHAKE_DONE', () {
      final original = HandshakeDoneFrame();
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<HandshakeDoneFrame>());
      expect(nextOffset, equals(bytes.length));
    });
  });
}

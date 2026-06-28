import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('PaddingFrame', () {
    test('serialize', () {
      final f = PaddingFrame(length: 3);
      expect(f.serialize(), equals(Uint8List(3)));
    });
  });

  group('PingFrame', () {
    test('serialize', () {
      final f = PingFrame();
      expect(f.serialize(), equals(Uint8List.fromList([0x01])));
    });
  });

  group('AckFrame', () {
    test('serialize/length', () {
      final f = AckFrame(
        largestAcknowledged: 100,
        ackDelay: 5,
        ackRanges: [AckRange(length: 10)],
      );
      final bytes = f.serialize();
      expect(bytes[0], equals(0x02));
      expect(bytes.length, greaterThan(3));
    });
  });

  group('ResetStreamFrame', () {
    test('serialize/round-trip values', () {
      final f = ResetStreamFrame(streamId: 4, errorCode: 42, finalSize: 1024);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x04));
      expect(bytes.length, greaterThan(3));
    });
  });

  group('StopSendingFrame', () {
    test('serialize', () {
      final f = StopSendingFrame(streamId: 8, errorCode: 1);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x05));
    });
  });

  group('CryptoFrame', () {
    test('serialize', () {
      final f = CryptoFrame(offset: 0, data: [0xAB, 0xCD]);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x06));
    });
  });

  group('NewTokenFrame', () {
    test('serialize', () {
      final f = NewTokenFrame(token: [0x01, 0x02, 0x03]);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x07));
    });
  });

  group('StreamFrame', () {
    test('minimal', () {
      final f = StreamFrame(streamId: 0, data: [0xFF]);
      expect(f.frameType, equals(0x0A)); // OFF=0, LEN=1, FIN=0
      final bytes = f.serialize();
      expect(bytes[0], equals(0x0A));
    });

    test('with FIN', () {
      final f = StreamFrame(streamId: 4, data: [0xAA], fin: true);
      expect(f.frameType & 0x01, isNonZero);
    });

    test('with offset', () {
      final f = StreamFrame(streamId: 8, data: [0xBB], offset: 100);
      expect(f.frameType & 0x04, isNonZero);
    });

    test('without explicit length', () {
      final f =
          StreamFrame(streamId: 12, data: [0xCC], hasExplicitLength: false);
      expect(f.frameType & 0x02, equals(0));
    });
  });

  group('MaxDataFrame', () {
    test('serialize', () {
      final f = MaxDataFrame(maxData: 4096);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x10));
    });
  });

  group('MaxStreamDataFrame', () {
    test('serialize', () {
      final f = MaxStreamDataFrame(streamId: 0, maxStreamData: 2048);
      final bytes = f.serialize();
      expect(bytes[0], equals(0x11));
    });
  });

  group('MaxStreamsFrame', () {
    test('bidi', () {
      final f = MaxStreamsFrame(maxStreams: 100, isUnidirectional: false);
      expect(f.frameType, equals(0x12));
    });
    test('uni', () {
      final f = MaxStreamsFrame(maxStreams: 50, isUnidirectional: true);
      expect(f.frameType, equals(0x13));
    });
  });

  group('DataBlockedFrame', () {
    test('serialize', () {
      final f = DataBlockedFrame(maxData: 1024);
      expect(f.serialize()[0], equals(0x14));
    });
  });

  group('StreamDataBlockedFrame', () {
    test('serialize', () {
      final f = StreamDataBlockedFrame(streamId: 0, maxStreamData: 512);
      expect(f.serialize()[0], equals(0x15));
    });
  });

  group('StreamsBlockedFrame', () {
    test('bidi', () {
      final f = StreamsBlockedFrame(maxStreams: 10, isUnidirectional: false);
      expect(f.frameType, equals(0x16));
    });
    test('uni', () {
      final f = StreamsBlockedFrame(maxStreams: 10, isUnidirectional: true);
      expect(f.frameType, equals(0x17));
    });
  });

  group('NewConnectionIdFrame', () {
    test('serialize', () {
      final f = NewConnectionIdFrame(
        sequenceNumber: 1,
        retirePriorTo: 0,
        connectionId: [0x01, 0x02],
        statelessResetToken: List<int>.filled(16, 0xAA),
      );
      expect(f.serialize()[0], equals(0x18));
    });

    test('invalid token length throws', () {
      expect(
        () => NewConnectionIdFrame(
          sequenceNumber: 1,
          retirePriorTo: 0,
          connectionId: [1],
          statelessResetToken: [1, 2, 3],
        ),
        throwsArgumentError,
      );
    });
  });

  group('RetireConnectionIdFrame', () {
    test('serialize', () {
      final f = RetireConnectionIdFrame(sequenceNumber: 5);
      expect(f.serialize()[0], equals(0x19));
    });
  });

  group('PathChallengeFrame', () {
    test('serialize', () {
      final f = PathChallengeFrame(data: List<int>.filled(8, 0xAB));
      expect(f.serialize()[0], equals(0x1a));
    });

    test('wrong length throws', () {
      expect(
        () => PathChallengeFrame(data: [1, 2, 3]),
        throwsArgumentError,
      );
    });
  });

  group('PathResponseFrame', () {
    test('serialize', () {
      final f = PathResponseFrame(data: List<int>.filled(8, 0xCD));
      expect(f.serialize()[0], equals(0x1b));
    });
  });

  group('ConnectionCloseFrame', () {
    test('transport with reason', () {
      final f = ConnectionCloseFrame(
          errorCode: 0x0100, offendingFrameType: 0x06, reasonPhrase: 'test');
      expect(f.serialize()[0], equals(0x1c));
    });
  });

  group('ApplicationCloseFrame', () {
    test('serialize', () {
      final f = ApplicationCloseFrame(errorCode: 0x0100, reasonPhrase: 'done');
      expect(f.serialize()[0], equals(0x1d));
    });
  });

  group('HandshakeDoneFrame', () {
    test('serialize', () {
      final f = HandshakeDoneFrame();
      expect(f.serialize(), equals(Uint8List.fromList([0x1e])));
    });
  });

  group('FrameCodec', () {
    test('serialize delegates to frame', () {
      final f = PingFrame();
      expect(FrameCodec.serialize(f), equals(f.serialize()));
    });
  });
}

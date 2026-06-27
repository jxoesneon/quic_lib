import 'package:test/test.dart';
import 'package:dart_quic/src/wire/frame.dart';

void main() {
  group('FrameCodec.parse — data-carrying frames', () {
    test('parse CRYPTO', () {
      final original = CryptoFrame(offset: 42, data: [0xAB, 0xCD, 0xEF]);
      final bytes = original.serialize();
      final (parsed, newOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<CryptoFrame>());
      final crypto = parsed as CryptoFrame;
      expect(crypto.frameType, equals(0x06));
      expect(crypto.offset, equals(42));
      expect(crypto.data, equals([0xAB, 0xCD, 0xEF]));
      expect(newOffset, equals(bytes.length));
    });

    test('parse NEW_TOKEN', () {
      final original = NewTokenFrame(token: [0x01, 0x02, 0x03, 0x04]);
      final bytes = original.serialize();
      final (parsed, newOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<NewTokenFrame>());
      final tokenFrame = parsed as NewTokenFrame;
      expect(tokenFrame.frameType, equals(0x07));
      expect(tokenFrame.token, equals([0x01, 0x02, 0x03, 0x04]));
      expect(newOffset, equals(bytes.length));
    });

    test('parse STREAM with FIN+LEN+OFF', () {
      final original = StreamFrame(
        streamId: 64,
        data: [0x11, 0x22],
        offset: 100,
        fin: true,
        hasExplicitLength: true,
      );
      final bytes = original.serialize();
      final (parsed, newOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamFrame>());
      final stream = parsed as StreamFrame;
      expect(stream.frameType, equals(0x0F));
      expect(stream.streamId, equals(64));
      expect(stream.data, equals([0x11, 0x22]));
      expect(stream.offset, equals(100));
      expect(stream.fin, isTrue);
      expect(stream.hasExplicitLength, isTrue);
      expect(newOffset, equals(bytes.length));
    });

    test('parse STREAM with no flags (minimal)', () {
      final original = StreamFrame(
        streamId: 0,
        data: [0xFF],
        hasExplicitLength: false,
        offset: null,
        fin: false,
      );
      final bytes = original.serialize();
      final (parsed, newOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamFrame>());
      final stream = parsed as StreamFrame;
      expect(stream.frameType, equals(0x08));
      expect(stream.streamId, equals(0));
      expect(stream.data, equals([0xFF]));
      expect(stream.offset, isNull);
      expect(stream.fin, isFalse);
      expect(stream.hasExplicitLength, isFalse);
      expect(newOffset, equals(bytes.length));
    });

    test('parse STREAM with FIN only', () {
      final original = StreamFrame(
        streamId: 4,
        data: [0xAA, 0xBB],
        fin: true,
        hasExplicitLength: false,
        offset: null,
      );
      final bytes = original.serialize();
      final (parsed, newOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamFrame>());
      final stream = parsed as StreamFrame;
      expect(stream.frameType, equals(0x09));
      expect(stream.streamId, equals(4));
      expect(stream.data, equals([0xAA, 0xBB]));
      expect(stream.offset, isNull);
      expect(stream.fin, isTrue);
      expect(stream.hasExplicitLength, isFalse);
      expect(newOffset, equals(bytes.length));
    });
  });
}

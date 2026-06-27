import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/wire/frame.dart';

void main() {
  group('FrameCodec.parse simple frames', () {
    test('parses PADDING', () {
      final frame = PaddingFrame(length: 1);
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<PaddingFrame>());
      expect((parsed as PaddingFrame).length, 1);
      expect(nextOffset, bytes.length);
    });

    test('parses PING', () {
      final frame = PingFrame();
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<PingFrame>());
      expect(nextOffset, bytes.length);
    });

    test('parses ACK with one range', () {
      final frame = AckFrame(
        largestAcknowledged: 100,
        ackDelay: 10,
        ackRanges: [AckRange(gap: 0, length: 5)],
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<AckFrame>());
      final ack = parsed as AckFrame;
      expect(ack.largestAcknowledged, 100);
      expect(ack.ackDelay, 10);
      expect(ack.ackRanges.length, 1);
      expect(ack.ackRanges[0].gap, 0);
      expect(ack.ackRanges[0].length, 5);
      expect(nextOffset, bytes.length);
    });

    test('parses RESET_STREAM', () {
      final frame = ResetStreamFrame(
        streamId: 42,
        errorCode: 7,
        finalSize: 1024,
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<ResetStreamFrame>());
      final rs = parsed as ResetStreamFrame;
      expect(rs.streamId, 42);
      expect(rs.errorCode, 7);
      expect(rs.finalSize, 1024);
      expect(nextOffset, bytes.length);
    });

    test('parses STOP_SENDING', () {
      final frame = StopSendingFrame(
        streamId: 99,
        errorCode: 3,
      );
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StopSendingFrame>());
      final ss = parsed as StopSendingFrame;
      expect(ss.streamId, 99);
      expect(ss.errorCode, 3);
      expect(nextOffset, bytes.length);
    });

    test('unsupported type still throws', () {
      final bytes = Uint8List.fromList([0x1f]); // unsupported frame type
      expect(() => FrameCodec.parse(bytes), throwsA(isA<UnsupportedError>()));
    });
  });
}

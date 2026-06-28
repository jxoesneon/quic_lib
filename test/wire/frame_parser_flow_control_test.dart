import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('Flow-control frame parsing', () {
    test('MAX_DATA (0x10)', () {
      final frame = MaxDataFrame(maxData: 12345);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<MaxDataFrame>());
      expect((parsed as MaxDataFrame).maxData, 12345);
      expect(offset, bytes.length);
    });

    test('MAX_STREAM_DATA (0x11)', () {
      final frame = MaxStreamDataFrame(streamId: 42, maxStreamData: 99999);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<MaxStreamDataFrame>());
      final maxStreamDataFrame = parsed as MaxStreamDataFrame;
      expect(maxStreamDataFrame.streamId, 42);
      expect(maxStreamDataFrame.maxStreamData, 99999);
      expect(offset, bytes.length);
    });

    test('MAX_STREAMS bidi (0x12)', () {
      final frame = MaxStreamsFrame(maxStreams: 100, isUnidirectional: false);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<MaxStreamsFrame>());
      final maxStreamsFrame = parsed as MaxStreamsFrame;
      expect(maxStreamsFrame.maxStreams, 100);
      expect(maxStreamsFrame.isUnidirectional, false);
      expect(maxStreamsFrame.frameType, 0x12);
      expect(offset, bytes.length);
    });

    test('MAX_STREAMS uni (0x13)', () {
      final frame = MaxStreamsFrame(maxStreams: 200, isUnidirectional: true);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<MaxStreamsFrame>());
      final maxStreamsFrame = parsed as MaxStreamsFrame;
      expect(maxStreamsFrame.maxStreams, 200);
      expect(maxStreamsFrame.isUnidirectional, true);
      expect(maxStreamsFrame.frameType, 0x13);
      expect(offset, bytes.length);
    });

    test('DATA_BLOCKED (0x14)', () {
      final frame = DataBlockedFrame(maxData: 55555);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<DataBlockedFrame>());
      expect((parsed as DataBlockedFrame).maxData, 55555);
      expect(offset, bytes.length);
    });

    test('STREAM_DATA_BLOCKED (0x15)', () {
      final frame = StreamDataBlockedFrame(streamId: 7, maxStreamData: 33333);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamDataBlockedFrame>());
      final streamDataBlockedFrame = parsed as StreamDataBlockedFrame;
      expect(streamDataBlockedFrame.streamId, 7);
      expect(streamDataBlockedFrame.maxStreamData, 33333);
      expect(offset, bytes.length);
    });

    test('STREAMS_BLOCKED bidi (0x16)', () {
      final frame =
          StreamsBlockedFrame(maxStreams: 50, isUnidirectional: false);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamsBlockedFrame>());
      final streamsBlockedFrame = parsed as StreamsBlockedFrame;
      expect(streamsBlockedFrame.maxStreams, 50);
      expect(streamsBlockedFrame.isUnidirectional, false);
      expect(streamsBlockedFrame.frameType, 0x16);
      expect(offset, bytes.length);
    });

    test('STREAMS_BLOCKED uni (0x17)', () {
      final frame = StreamsBlockedFrame(maxStreams: 75, isUnidirectional: true);
      final bytes = frame.serialize();
      final (parsed, offset) = FrameCodec.parse(bytes);
      expect(parsed, isA<StreamsBlockedFrame>());
      final streamsBlockedFrame = parsed as StreamsBlockedFrame;
      expect(streamsBlockedFrame.maxStreams, 75);
      expect(streamsBlockedFrame.isUnidirectional, true);
      expect(streamsBlockedFrame.frameType, 0x17);
      expect(offset, bytes.length);
    });
  });
}

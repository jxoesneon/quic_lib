import 'dart:typed_data';

import 'package:dart_quic/src/streams/flow_controller.dart';
import 'package:dart_quic/src/streams/quic_stream.dart';
import 'package:dart_quic/src/streams/stream_manager.dart';
import 'package:dart_quic/src/streams/stream_scheduler.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:test/test.dart';

class _TestScheduler implements StreamScheduler {
  final int _selected;
  _TestScheduler(this._selected);

  @override
  int selectNextStream(List<int> activeStreamIds) => _selected;
}

void main() {
  group('StreamManager core', () {
    test('onStreamFrame creates a new stream', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
      );

      manager.onStreamFrame(frame);

      expect(manager.getStream(0), isNotNull);
      expect(manager.getStream(0)!.streamId, equals(0));
    });

    test('onStreamFrame on existing stream does not recreate', () {
      final manager = StreamManager();
      final frame1 = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
      );
      final frame2 = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([4, 5]),
        fin: true,
      );

      manager.onStreamFrame(frame1);
      final stream1 = manager.getStream(0);
      manager.onStreamFrame(frame2);
      final stream2 = manager.getStream(0);

      expect(stream1, same(stream2));
    });

    test('onStreamFrame handles non-Uint8List data', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: <int>[1, 2, 3],
      );

      manager.onStreamFrame(frame);

      expect(manager.getStream(0), isNotNull);
    });

    test('onStreamFrame with fin sets final size', () async {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
        fin: true,
      );

      manager.onStreamFrame(frame);
      final stream = manager.getStream(0)! as QuicReceiveStream;
      await stream.done;
    });

    test('getStream returns null for unknown stream', () {
      final manager = StreamManager();
      expect(manager.getStream(99), isNull);
    });

    test('getSendFlowController returns null for unknown stream', () {
      final manager = StreamManager();
      expect(manager.getSendFlowController(99), isNull);
    });

    test('getReceiveFlowController returns null for unknown stream', () {
      final manager = StreamManager();
      expect(manager.getReceiveFlowController(99), isNull);
    });

    test('streams returns all active streams', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      manager.onStreamFrame(StreamFrame(streamId: 4, data: Uint8List(1)));

      final ids = manager.streams.map((s) => s.streamId).toList();
      expect(ids, contains(0));
      expect(ids, contains(4));
    });

    test('streamIds returns all active stream IDs', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      manager.onStreamFrame(StreamFrame(streamId: 4, data: Uint8List(1)));

      final ids = manager.streamIds.toList();
      expect(ids, contains(0));
      expect(ids, contains(4));
    });

    test('selectNextStream returns null when no streams', () {
      final manager = StreamManager();
      expect(manager.selectNextStream(), isNull);
    });

    test('selectNextStream returns first stream without scheduler', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      manager.onStreamFrame(StreamFrame(streamId: 4, data: Uint8List(1)));

      expect(manager.selectNextStream()?.streamId, equals(0));
    });

    test('selectNextStream uses scheduler when set', () {
      final manager = StreamManager();
      manager.scheduler = _TestScheduler(4);
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      manager.onStreamFrame(StreamFrame(streamId: 4, data: Uint8List(1)));

      expect(manager.selectNextStream()?.streamId, equals(4));
    });

    test('removeStream removes the stream', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      expect(manager.getStream(0), isNotNull);

      manager.removeStream(0);
      expect(manager.getStream(0), isNull);
    });

    test('reset clears all streams', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));
      manager.onStreamFrame(StreamFrame(streamId: 4, data: Uint8List(1)));

      manager.reset();

      expect(manager.getStream(0), isNull);
      expect(manager.getStream(4), isNull);
      expect(manager.streams, isEmpty);
    });

    test('canSendOnStream returns false for unknown stream', () {
      final manager = StreamManager();
      expect(manager.canSendOnStream(0, 100), isFalse);
    });

    test('canSendOnStream returns false when window too small', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(0)));
      expect(manager.canSendOnStream(0, 70000), isFalse);
    });

    test('canSendOnStream returns true when window is sufficient', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(0)));
      expect(manager.canSendOnStream(0, 65536), isTrue);
    });

    test('updateSendWindow updates the controller', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(0)));
      expect(manager.canSendOnStream(0, 70000), isFalse);

      manager.updateSendWindow(0, 131072);
      expect(manager.canSendOnStream(0, 70000), isTrue);
    });

    test('updateSendWindow on unknown stream is no-op', () {
      final manager = StreamManager();
      expect(() => manager.updateSendWindow(99, 100000), returnsNormally);
    });

    test('resetFlowControl clears controllers but keeps streams', () {
      final manager = StreamManager();
      manager.onStreamFrame(StreamFrame(streamId: 0, data: Uint8List(1)));

      manager.resetFlowControl();

      expect(manager.getStream(0), isNotNull);
      expect(manager.getSendFlowController(0), isNull);
      expect(manager.getReceiveFlowController(0), isNull);
    });

    test('onStreamFrame with offset sets bytes correctly', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
        offset: 10,
      );
      manager.onStreamFrame(frame);
      expect(manager.getStream(0), isNotNull);
    });

    test('receiveFlowController consume reduces window', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3, 4, 5]),
      );
      manager.onStreamFrame(frame);

      final fc = manager.getReceiveFlowController(0);
      expect(fc, isNotNull);
      expect(fc!.availableWindow, equals(65536 - 5));
    });
  });
}

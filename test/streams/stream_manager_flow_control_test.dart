import 'dart:typed_data';

import 'package:quic_lib/src/streams/stream_manager.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('StreamManager flow control', () {
    test('new stream gets flow controllers', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
      );

      manager.onStreamFrame(frame);

      final sendFc = manager.getSendFlowController(0);
      final receiveFc = manager.getReceiveFlowController(0);

      expect(sendFc, isNotNull);
      expect(receiveFc, isNotNull);
      expect(sendFc!.availableWindow, equals(65536));
      expect(receiveFc!.availableWindow, equals(65533));
    });

    test('receiving STREAM frame consumes receive window', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3, 4, 5]),
      );

      manager.onStreamFrame(frame);

      final receiveFc = manager.getReceiveFlowController(0);
      expect(receiveFc, isNotNull);
      expect(receiveFc!.availableWindow, equals(65536 - 5));
    });

    test('canSendOnStream respects window limit', () {
      final manager = StreamManager();
      final frame = StreamFrame(streamId: 0, data: Uint8List(0));

      manager.onStreamFrame(frame);

      expect(manager.canSendOnStream(0, 100), isTrue);
      expect(manager.canSendOnStream(0, 65536), isTrue);
      expect(manager.canSendOnStream(0, 65537), isFalse);
      expect(manager.canSendOnStream(0, 0), isTrue);
    });

    test('updateSendWindow increases available window', () {
      final manager = StreamManager();
      final frame = StreamFrame(streamId: 0, data: Uint8List(0));

      manager.onStreamFrame(frame);

      expect(manager.canSendOnStream(0, 70000), isFalse);

      manager.updateSendWindow(0, 131072);

      expect(manager.canSendOnStream(0, 70000), isTrue);
    });

    test('resetFlowControl clears all controllers', () {
      final manager = StreamManager();
      final frame = StreamFrame(
        streamId: 0,
        data: Uint8List.fromList([1, 2, 3]),
      );

      manager.onStreamFrame(frame);

      expect(manager.getSendFlowController(0), isNotNull);
      expect(manager.getReceiveFlowController(0), isNotNull);

      manager.resetFlowControl();

      expect(manager.getSendFlowController(0), isNull);
      expect(manager.getReceiveFlowController(0), isNull);
    });
  });
}

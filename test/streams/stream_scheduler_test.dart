import 'dart:typed_data';

import 'package:dart_quic/src/streams/round_robin_scheduler.dart';
import 'package:dart_quic/src/streams/stream_manager.dart';
import 'package:dart_quic/src/streams/stream_scheduler.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('RoundRobinScheduler', () {
    test('cycles through stream IDs in order', () {
      final scheduler = RoundRobinScheduler();
      const ids = [0, 4, 8];
      expect(scheduler.selectNextStream(ids), equals(0));
      expect(scheduler.selectNextStream(ids), equals(4));
      expect(scheduler.selectNextStream(ids), equals(8));
    });

    test('wraps around to the first ID', () {
      final scheduler = RoundRobinScheduler();
      const ids = [0, 4];
      expect(scheduler.selectNextStream(ids), equals(0));
      expect(scheduler.selectNextStream(ids), equals(4));
      expect(scheduler.selectNextStream(ids), equals(0));
    });

    test('throws when activeStreamIds is empty', () {
      final scheduler = RoundRobinScheduler();
      expect(() => scheduler.selectNextStream([]), throwsArgumentError);
    });

    test('sorts unsorted IDs', () {
      final scheduler = RoundRobinScheduler();
      const ids = [8, 0, 4];
      expect(scheduler.selectNextStream(ids), equals(0));
      expect(scheduler.selectNextStream(ids), equals(4));
      expect(scheduler.selectNextStream(ids), equals(8));
      expect(scheduler.selectNextStream(ids), equals(0));
    });
  });

  group('StreamManager with scheduler', () {
    test('selectNextStream returns null when no streams exist', () {
      final manager = StreamManager();
      expect(manager.selectNextStream(), isNull);
    });

    test('selectNextStream returns first stream without scheduler', () {
      final manager = StreamManager();
      final frame1 = StreamFrame(streamId: 0, data: Uint8List.fromList([1]));
      final frame2 = StreamFrame(streamId: 4, data: Uint8List.fromList([2]));
      manager.onStreamFrame(frame1);
      manager.onStreamFrame(frame2);
      expect(manager.selectNextStream()?.streamId, equals(0));
    });

    test('selectNextStream uses scheduler when set', () {
      final manager = StreamManager();
      final scheduler = RoundRobinScheduler();
      manager.scheduler = scheduler;

      final frame1 = StreamFrame(streamId: 0, data: Uint8List.fromList([1]));
      final frame2 = StreamFrame(streamId: 4, data: Uint8List.fromList([2]));
      manager.onStreamFrame(frame1);
      manager.onStreamFrame(frame2);

      expect(manager.selectNextStream()?.streamId, equals(0));
      expect(manager.selectNextStream()?.streamId, equals(4));
      expect(manager.selectNextStream()?.streamId, equals(0));
    });

    test('scheduler setter overrides previous scheduler', () {
      final manager = StreamManager();
      final scheduler1 = RoundRobinScheduler();
      final scheduler2 = RoundRobinScheduler();
      manager.scheduler = scheduler1;
      manager.scheduler = scheduler2;
      // Verify it doesn't throw and can be used.
      final frame = StreamFrame(streamId: 0, data: Uint8List.fromList([1]));
      manager.onStreamFrame(frame);
      expect(manager.selectNextStream()?.streamId, equals(0));
    });
  });
}

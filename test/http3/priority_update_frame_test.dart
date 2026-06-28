import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/priority_update_frame.dart';
import 'package:test/test.dart';

void main() {
  group('PriorityUpdateFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = PriorityUpdateFrame(
        streamId: 42,
        priorityFieldValue: 'u=3, i',
      );
      final payload = frame.serializePayload();
      final parsed = PriorityUpdateFrame.parsePayload(payload);

      expect(parsed, equals(frame));
      expect(parsed.streamId, equals(42));
      expect(parsed.priorityFieldValue, equals('u=3, i'));
    });

    test('various priority field values', () {
      final values = [
        '',
        'u=0',
        'u=7, i',
        'u=3, i, q=0.5',
        'u=6',
      ];
      for (final value in values) {
        final frame = PriorityUpdateFrame(
          streamId: 99,
          priorityFieldValue: value,
        );
        final payload = frame.serializePayload();
        final parsed = PriorityUpdateFrame.parsePayload(payload);
        expect(parsed.priorityFieldValue, equals(value),
            reason: 'Failed for priority value "$value"');
      }
    });

    test('toFrame produces correct type', () {
      final priorityFrame = PriorityUpdateFrame(
        streamId: 7,
        priorityFieldValue: 'u=1',
      );
      final frame = priorityFrame.toFrame();

      expect(frame.type, equals(Http3FrameType.priorityUpdate));
      expect(frame.payload, equals(priorityFrame.serializePayload()));
    });

    test('parse alias works', () {
      final frame = PriorityUpdateFrame(
        streamId: 5,
        priorityFieldValue: 'u=2, i',
      );
      final bytes = frame.serializePayload();
      final parsed = PriorityUpdateFrame.parse(bytes);
      expect(parsed, equals(frame));
    });

    test('serialize alias equals serializePayload', () {
      final frame = PriorityUpdateFrame(
        streamId: 3,
        priorityFieldValue: 'u=0',
      );
      expect(frame.serialize(), equals(frame.serializePayload()));
    });

    test('getByteLength matches full frame size', () {
      final frame = PriorityUpdateFrame(
        streamId: 100,
        priorityFieldValue: 'u=3, i',
      );
      final fullFrame = frame.toFrame().serialize();
      expect(frame.getByteLength(), equals(fullFrame.length));
    });

    test('throws on empty payload', () {
      expect(
        () => PriorityUpdateFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('large stream ID handled correctly', () {
      final frame = PriorityUpdateFrame(
        streamId: 1073741823,
        priorityFieldValue: 'u=7',
      );
      final payload = frame.serializePayload();
      final parsed = PriorityUpdateFrame.parsePayload(payload);

      expect(parsed.streamId, equals(1073741823));
      expect(parsed, equals(frame));
    });

    test('toString includes streamId and priority', () {
      final frame = PriorityUpdateFrame(
        streamId: 12,
        priorityFieldValue: 'u=3',
      );
      expect(frame.toString(), contains('12'));
      expect(frame.toString(), contains('u=3'));
    });

    test('hashCode is consistent', () {
      final a = PriorityUpdateFrame(streamId: 1, priorityFieldValue: 'u=0');
      final b = PriorityUpdateFrame(streamId: 1, priorityFieldValue: 'u=0');
      expect(a.hashCode, equals(b.hashCode));
    });

    test('equals returns false for different type', () {
      final frame = PriorityUpdateFrame(streamId: 1, priorityFieldValue: 'u=0');
      expect(frame == 'not a frame', isFalse);
    });
  });

  group('PriorityUpdatePushFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = PriorityUpdatePushFrame(
        streamId: 10,
        priorityFieldValue: 'u=4, i',
      );
      final payload = frame.serializePayload();
      final parsed = PriorityUpdatePushFrame.parsePayload(payload);

      expect(parsed, equals(frame));
      expect(parsed.streamId, equals(10));
      expect(parsed.priorityFieldValue, equals('u=4, i'));
    });

    test('toFrame produces correct type', () {
      final pushFrame = PriorityUpdatePushFrame(
        streamId: 8,
        priorityFieldValue: 'u=2',
      );
      final frame = pushFrame.toFrame();

      expect(frame.type, equals(Http3FrameType.priorityUpdatePush));
      expect(frame.payload, equals(pushFrame.serializePayload()));
    });

    test('getByteLength matches full frame size', () {
      final frame = PriorityUpdatePushFrame(
        streamId: 5,
        priorityFieldValue: 'u=6',
      );
      final fullFrame = frame.toFrame().serialize();
      expect(frame.getByteLength(), equals(fullFrame.length));
    });

    test('throws on empty payload', () {
      expect(
        () => PriorityUpdatePushFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('empty priority field value works', () {
      final frame = PriorityUpdatePushFrame(
        streamId: 0,
        priorityFieldValue: '',
      );
      final payload = frame.serializePayload();
      expect(payload.length, equals(1)); // only the VarInt for streamId

      final parsed = PriorityUpdatePushFrame.parsePayload(payload);
      expect(parsed.streamId, equals(0));
      expect(parsed.priorityFieldValue, isEmpty);
      expect(parsed, equals(frame));
    });
  });
}

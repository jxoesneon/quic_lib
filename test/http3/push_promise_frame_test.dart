import 'dart:typed_data';

import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:dart_quic/src/http3/push_promise_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3PushPromiseFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: Uint8List.fromList([0x01, 0x02, 0x03, 0x04]),
      );
      final payload = frame.serializePayload();
      final parsed = Http3PushPromiseFrame.parsePayload(payload);

      expect(parsed, equals(frame));
    });

    test('toFrame produces correct type', () {
      final pushPromise = Http3PushPromiseFrame(
        pushId: 99,
        encodedFieldSection: Uint8List.fromList([0xAA, 0xBB]),
      );
      final frame = pushPromise.toFrame();

      expect(frame.type, equals(Http3FrameType.pushPromise));
      expect(frame.payload, equals(pushPromise.serializePayload()));
    });

    test('empty field section works', () {
      final frame = Http3PushPromiseFrame(
        pushId: 0,
        encodedFieldSection: Uint8List(0),
      );
      final payload = frame.serializePayload();
      expect(payload.length, equals(1)); // only the VarInt for pushId

      final parsed = Http3PushPromiseFrame.parsePayload(payload);
      expect(parsed.pushId, equals(0));
      expect(parsed.encodedFieldSection, isEmpty);
      expect(parsed, equals(frame));
    });

    test('large push ID handled correctly', () {
      final frame = Http3PushPromiseFrame(
        pushId: 16383,
        encodedFieldSection: Uint8List.fromList([0xFF]),
      );
      final payload = frame.serializePayload();
      final parsed = Http3PushPromiseFrame.parsePayload(payload);

      expect(parsed.pushId, equals(16383));
      expect(parsed, equals(frame));
    });

    test('throws on empty payload', () {
      expect(
        () => Http3PushPromiseFrame.parsePayload(Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}

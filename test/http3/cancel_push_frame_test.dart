import 'dart:typed_data';

import 'package:dart_quic/src/http3/cancel_push_frame.dart';
import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:test/test.dart';

void main() {
  group('Http3CancelPushFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3CancelPushFrame(pushId: 12);
      final payload = frame.serializePayload();
      final parsed = Http3CancelPushFrame.parsePayload(payload);

      expect(parsed, equals(frame));
    });

    test('toFrame produces correct type', () {
      final cancelPush = Http3CancelPushFrame(pushId: 42);
      final frame = cancelPush.toFrame();

      expect(frame.type, equals(Http3FrameType.cancelPush));
      expect(frame.payload, equals(cancelPush.serializePayload()));
    });

    test('large push ID handled correctly', () {
      final frame = Http3CancelPushFrame(pushId: 1073741823);
      final payload = frame.serializePayload();
      final parsed = Http3CancelPushFrame.parsePayload(payload);

      expect(parsed.pushId, equals(1073741823));
      expect(parsed, equals(frame));
    });

    test('serialize alias works', () {
      final frame = Http3CancelPushFrame(pushId: 5);
      expect(frame.serialize(), equals(frame.serializePayload()));
    });

    test('parse alias works', () {
      final frame = Http3CancelPushFrame(pushId: 7);
      final bytes = frame.serializePayload();
      final parsed = Http3CancelPushFrame.parse(bytes);
      expect(parsed, equals(frame));
    });

    test('parsePayload throws for empty payload', () {
      expect(
        () => Http3CancelPushFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('toString includes pushId', () {
      final frame = Http3CancelPushFrame(pushId: 99);
      expect(frame.toString(), contains('99'));
    });

    test('hashCode is consistent', () {
      final a = Http3CancelPushFrame(pushId: 42);
      final b = Http3CancelPushFrame(pushId: 42);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('equals returns false for different type', () {
      final frame = Http3CancelPushFrame(pushId: 42);
      expect(frame == 'not a frame', isFalse);
    });
  });
}

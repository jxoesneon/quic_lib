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
  });
}

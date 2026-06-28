import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/max_push_id_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3MaxPushIdFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3MaxPushIdFrame(pushId: 12);
      final payload = frame.serializePayload();
      final parsed = Http3MaxPushIdFrame.parsePayload(payload);

      expect(parsed, equals(frame));
    });

    test('toFrame produces correct type', () {
      final maxPushId = Http3MaxPushIdFrame(pushId: 42);
      final frame = maxPushId.toFrame();

      expect(frame.type, equals(Http3FrameType.maxPushId));
      expect(frame.payload, equals(maxPushId.serializePayload()));
    });

    test('large push ID handled correctly', () {
      final frame = Http3MaxPushIdFrame(pushId: 1073741823);
      final payload = frame.serializePayload();
      final parsed = Http3MaxPushIdFrame.parsePayload(payload);

      expect(parsed.pushId, equals(1073741823));
      expect(parsed, equals(frame));
    });
  });
}

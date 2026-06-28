import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/goaway_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3GoawayFrame', () {
    test('serializePayload / parsePayload round-trip', () {
      final frame = Http3GoawayFrame(lastStreamIdOrPushId: 12);
      final payload = frame.serializePayload();
      final parsed = Http3GoawayFrame.parsePayload(payload);

      expect(parsed, equals(frame));
    });

    test('toFrame produces correct type and payload', () {
      final goaway = Http3GoawayFrame(lastStreamIdOrPushId: 42);
      final frame = goaway.toFrame();

      expect(frame.type, equals(Http3FrameType.goaway));
      expect(frame.payload, equals(goaway.serializePayload()));
    });

    test('large stream ID handled correctly', () {
      final frame = Http3GoawayFrame(lastStreamIdOrPushId: 1073741823);
      final payload = frame.serializePayload();
      final parsed = Http3GoawayFrame.parsePayload(payload);

      expect(parsed.lastStreamIdOrPushId, equals(1073741823));
      expect(parsed, equals(frame));
    });
  });
}

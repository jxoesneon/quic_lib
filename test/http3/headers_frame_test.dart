import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3HeadersFrame', () {
    test('toFrame produces HEADERS type', () {
      final headers = Http3HeadersFrame(
        encodedFieldSection: [0x01, 0x02, 0x03],
      );
      final frame = headers.toFrame();

      expect(frame.type, equals(Http3FrameType.headers));
      expect(frame.payload, equals(headers.encodedFieldSection));
    });

    test('fromPayload round-trip', () {
      final original = Http3HeadersFrame(
        encodedFieldSection: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final frame = original.toFrame();
      final parsed = Http3HeadersFrame.fromPayload(frame.payload);

      expect(parsed, equals(original));
    });

    test('empty field section works', () {
      final headers = Http3HeadersFrame(encodedFieldSection: []);
      final frame = headers.toFrame();

      expect(frame.type, equals(Http3FrameType.headers));
      expect(frame.payload, isEmpty);

      final parsed = Http3HeadersFrame.fromPayload(frame.payload);
      expect(parsed.encodedFieldSection, isEmpty);
      expect(parsed, equals(headers));
    });
  });
}

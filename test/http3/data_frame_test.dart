import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:test/test.dart';

void main() {
  group('Http3DataFrame', () {
    test('toFrame produces DATA type', () {
      final dataFrame = Http3DataFrame(
        data: [0x01, 0x02, 0x03],
      );
      final frame = dataFrame.toFrame();

      expect(frame.type, equals(Http3FrameType.data));
      expect(frame.payload, equals(dataFrame.data));
    });

    test('fromPayload round-trip', () {
      final original = Http3DataFrame(
        data: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final frame = original.toFrame();
      final parsed = Http3DataFrame.fromPayload(frame.payload);

      expect(parsed, equals(original));
    });

    test('empty data frame', () {
      final dataFrame = Http3DataFrame.empty();
      final frame = dataFrame.toFrame();

      expect(frame.type, equals(Http3FrameType.data));
      expect(frame.payload, isEmpty);

      final parsed = Http3DataFrame.fromPayload(frame.payload);
      expect(parsed.data, isEmpty);
      expect(parsed, equals(dataFrame));
    });

    test('large data preserved', () {
      final largeData = List<int>.generate(10000, (i) => i % 256);
      final original = Http3DataFrame(data: largeData);
      final frame = original.toFrame();

      expect(frame.type, equals(Http3FrameType.data));
      expect(frame.payload, equals(largeData));

      final parsed = Http3DataFrame.fromPayload(frame.payload);
      expect(parsed.data, equals(largeData));
      expect(parsed, equals(original));
    });
  });
}

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('PathChallengeFrame', () {
    test('serialize/parse round-trip', () {
      final original = PathChallengeFrame(
        data: Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
      );
      final bytes = original.serialize();
      final parsed = PathChallengeFrame.parse(bytes);

      expect(parsed.data, equals(original.data));
      expect(parsed.frameType, equals(0x1a));
    });

    test('data is exactly 8 bytes', () {
      final frame = PathChallengeFrame();
      expect(frame.data.length, equals(8));
    });

    test('random data generation produces different values', () {
      final frame1 = PathChallengeFrame();
      final frame2 = PathChallengeFrame();
      expect(frame1.data, isNot(equals(frame2.data)));
    });

    test('byteLength is 9', () {
      final frame = PathChallengeFrame();
      expect(frame.byteLength, equals(9));
    });

    test('wrong length throws', () {
      expect(
        () => PathChallengeFrame(data: [1, 2, 3]),
        throwsArgumentError,
      );
    });

    test('parse with insufficient bytes throws', () {
      expect(
        () => PathChallengeFrame.parse(Uint8List.fromList([0x1a, 0x00])),
        throwsArgumentError,
      );
    });

    test('FrameCodec parse round-trip', () {
      final original = PathChallengeFrame(
        data: Uint8List.fromList([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]),
      );
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);

      expect(parsed, isA<PathChallengeFrame>());
      expect((parsed as PathChallengeFrame).data, equals(original.data));
      expect(nextOffset, equals(bytes.length));
    });
  });

  group('PathResponseFrame', () {
    test('serialize/parse round-trip', () {
      final original = PathResponseFrame(
        data: Uint8List.fromList([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
      );
      final bytes = original.serialize();
      final parsed = PathResponseFrame.parse(bytes);

      expect(parsed.data, equals(original.data));
      expect(parsed.frameType, equals(0x1b));
    });

    test('data is exactly 8 bytes', () {
      final frame = PathResponseFrame(
        data: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
      );
      expect(frame.data.length, equals(8));
    });

    test('byteLength is 9', () {
      final frame = PathResponseFrame(
        data: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
      );
      expect(frame.byteLength, equals(9));
    });

    test('wrong length throws', () {
      expect(
        () => PathResponseFrame(data: [1, 2, 3]),
        throwsArgumentError,
      );
    });

    test('parse with insufficient bytes throws', () {
      expect(
        () => PathResponseFrame.parse(Uint8List.fromList([0x1b, 0x00])),
        throwsArgumentError,
      );
    });

    test('FrameCodec parse round-trip', () {
      final original = PathResponseFrame(
        data: Uint8List.fromList([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]),
      );
      final bytes = original.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);

      expect(parsed, isA<PathResponseFrame>());
      expect((parsed as PathResponseFrame).data, equals(original.data));
      expect(nextOffset, equals(bytes.length));
    });
  });
}

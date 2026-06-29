import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:test/test.dart';

/// Fuzz/error-path tests for the HTTP/3 frame parser.
///
/// Verifies that malformed, truncated, and unknown-frame-type inputs are
/// rejected with [ArgumentError].
void main() {
  group('Http3Frame.parse malformed input', () {
    test('empty buffer throws ArgumentError', () {
      expect(() => Http3Frame.parse(Uint8List(0)), throwsArgumentError);
    });

    test('out-of-bounds offset throws ArgumentError', () {
      final bytes =
          Http3Frame(type: Http3FrameType.data, payload: [0x01]).serialize();
      expect(() => Http3Frame.parse(bytes, offset: -1), throwsArgumentError);
      expect(() => Http3Frame.parse(bytes, offset: bytes.length + 1),
          throwsArgumentError);
    });

    test('truncated frame type throws ArgumentError', () {
      final bytes = Uint8List.fromList([0x40]); // 2-byte type, only first byte
      expect(() => Http3Frame.parse(bytes), throwsArgumentError);
    });

    test('truncated frame length throws ArgumentError', () {
      // 1-byte type + 2-byte length prefix with only 1 byte.
      final bytes = Uint8List.fromList([0x00, 0x40]);
      expect(() => Http3Frame.parse(bytes), throwsArgumentError);
    });

    test('truncated payload throws ArgumentError', () {
      // Type=0, length=5, but only 3 payload bytes.
      final bytes = Uint8List.fromList([0x00, 0x05, 0x01, 0x02, 0x03]);
      expect(() => Http3Frame.parse(bytes), throwsArgumentError);
    });

    test('unknown frame type throws ArgumentError', () {
      // Type value 0x99 is not a known HTTP/3 frame type.
      final bytes = Uint8List.fromList([
        0x99,
        0x00,
      ]);
      expect(() => Http3Frame.parse(bytes), throwsArgumentError);
    });

    test('random byte streams are rejected cleanly', () {
      final random = Random(42);
      for (var i = 0; i < 300; i++) {
        final len = random.nextInt(32) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        try {
          Http3Frame.parse(bytes);
        } on ArgumentError catch (_) {
          // Expected.
        }
      }
    });

    test('valid frames round-trip', () {
      for (final type in Http3FrameType.values) {
        final frame = Http3Frame(type: type, payload: [0x01, 0x02, 0x03]);
        final bytes = frame.serialize();
        final (parsed, consumed) = Http3Frame.parse(bytes);
        expect(parsed.type, equals(type));
        expect(parsed.payload, equals([0x01, 0x02, 0x03]));
        expect(consumed, equals(bytes.length));
      }
    });
  });
}

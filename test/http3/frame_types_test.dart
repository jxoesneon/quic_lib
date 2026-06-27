import 'dart:typed_data';

import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:test/test.dart';

void main() {
  group('Http3Frame.serialize', () {
    test('produces valid bytes for DATA frame', () {
      final frame = Http3Frame(
        type: Http3FrameType.data,
        payload: Uint8List.fromList([0x01, 0x02, 0x03]),
      );
      final bytes = frame.serialize();
      // Type = 0x00 (1 byte), Length = 0x03 (1 byte), Payload = 3 bytes
      expect(
        bytes,
        equals(Uint8List.fromList([0x00, 0x03, 0x01, 0x02, 0x03])),
      );
    });

    test('produces valid bytes for SETTINGS frame with empty payload', () {
      final frame = Http3Frame(
        type: Http3FrameType.settings,
        payload: Uint8List(0),
      );
      final bytes = frame.serialize();
      // Type = 0x04 (1 byte), Length = 0x00 (1 byte)
      expect(bytes, equals(Uint8List.fromList([0x04, 0x00])));
    });
  });

  group('Http3Frame.parse', () {
    test('round-trips a HEADERS frame', () {
      final original = Http3Frame(
        type: Http3FrameType.headers,
        payload: Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]),
      );
      final bytes = original.serialize();
      final (parsed, consumed) = Http3Frame.parse(bytes);
      expect(consumed, equals(bytes.length));
      expect(parsed.type, equals(original.type));
      expect(parsed.payload, equals(original.payload));
    });

    test('preserves all known frame types', () {
      for (final frameType in Http3FrameType.values) {
        final frame = Http3Frame(
          type: frameType,
          payload: Uint8List.fromList([0xAB]),
        );
        final bytes = frame.serialize();
        final (parsed, _) = Http3Frame.parse(bytes);
        expect(
          parsed.type,
          equals(frameType),
          reason: 'Frame type ${frameType.name} was not preserved',
        );
      }
    });

    test('handles empty payload', () {
      final frame = Http3Frame(
        type: Http3FrameType.settings,
        payload: Uint8List(0),
      );
      final bytes = frame.serialize();
      final (parsed, consumed) = Http3Frame.parse(bytes);
      expect(consumed, equals(2));
      expect(parsed.type, equals(Http3FrameType.settings));
      expect(parsed.payload, isEmpty);
    });

    test('parses correctly with non-zero offset', () {
      final frame = Http3Frame(
        type: Http3FrameType.goaway,
        payload: Uint8List.fromList([0x01, 0x02]),
      );
      final bytes = frame.serialize();
      // Prefix with garbage byte and suffix with trailing byte
      final prefixed = Uint8List.fromList([0xFF, ...bytes, 0xAA]);
      final (parsed, consumed) = Http3Frame.parse(prefixed, offset: 1);
      expect(consumed, equals(bytes.length));
      expect(parsed.type, equals(Http3FrameType.goaway));
      expect(parsed.payload, equals(frame.payload));
    });
  });
}

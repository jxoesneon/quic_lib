import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/origin_frame.dart';
import 'package:test/test.dart';

void main() {
  group('OriginFrame', () {
    test('serializePayload / parsePayload round-trip with multiple origins',
        () {
      final frame = OriginFrame(
        origins: [
          'https://example.com',
          'https://example.org:8443',
        ],
      );
      final payload = frame.serializePayload();
      final parsed = OriginFrame.parsePayload(payload);

      expect(parsed, equals(frame));
      expect(parsed.origins, equals(frame.origins));
    });

    test('empty origins list', () {
      final frame = OriginFrame(origins: []);
      final payload = frame.serializePayload();
      expect(payload, isEmpty);

      final parsed = OriginFrame.parsePayload(payload);
      expect(parsed.origins, isEmpty);
      expect(parsed, equals(frame));
    });

    test('toFrame produces correct type', () {
      final originFrame = OriginFrame(
        origins: ['https://example.com'],
      );
      final frame = originFrame.toFrame();

      expect(frame.type, equals(Http3FrameType.origin));
      expect(frame.payload, equals(originFrame.serializePayload()));
    });

    test('parse alias works', () {
      final frame = OriginFrame(
        origins: ['https://foo.bar:8443'],
      );
      final bytes = frame.serializePayload();
      final parsed = OriginFrame.parse(bytes);
      expect(parsed, equals(frame));
    });

    test('serialize alias equals serializePayload', () {
      final frame = OriginFrame(origins: ['https://example.com']);
      expect(frame.serialize(), equals(frame.serializePayload()));
    });

    test('getByteLength matches full frame size', () {
      final frame = OriginFrame(
        origins: ['https://example.com', 'https://example.org'],
      );
      final fullFrame = frame.toFrame().serialize();
      expect(frame.getByteLength(), equals(fullFrame.length));
    });

    test('toString includes origins', () {
      final frame = OriginFrame(origins: ['https://example.com']);
      expect(frame.toString(), contains('https://example.com'));
    });

    test('hashCode is consistent', () {
      final a = OriginFrame(origins: ['https://a.com']);
      final b = OriginFrame(origins: ['https://a.com']);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('equals returns false for different type', () {
      final frame = OriginFrame(origins: ['https://a.com']);
      expect(frame == 'not a frame', isFalse);
    });

    test('parsePayload throws when origin length exceeds payload', () {
      // Craft a payload that claims an origin of length 100 but only has 2 bytes.
      final badPayload = Uint8List.fromList([0x40, 0x64, 0x01, 0x02]);
      expect(
        () => OriginFrame.parsePayload(badPayload),
        throwsArgumentError,
      );
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/http3/cancel_push_frame.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/push_promise_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3PushPromiseFrame', () {
    test('serialize / parse round-trip', () {
      final frame = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: Uint8List.fromList([0x01, 0x02, 0x03, 0x04]),
      );
      final bytes = frame.serialize();
      final parsed = Http3PushPromiseFrame.parse(bytes);

      expect(parsed.pushId, equals(frame.pushId));
      expect(parsed.encodedFieldSection, equals(frame.encodedFieldSection));
    });
  });

  group('Http3CancelPushFrame', () {
    test('serialize / parse round-trip', () {
      final frame = Http3CancelPushFrame(pushId: 12);
      final bytes = frame.serialize();
      final parsed = Http3CancelPushFrame.parse(bytes);

      expect(parsed.pushId, equals(frame.pushId));
    });
  });

  group('Http3FrameType', () {
    test('includes pushPromise and cancelPush', () {
      expect(Http3FrameType.pushPromise.value, equals(0x05));
      expect(Http3FrameType.cancelPush.value, equals(0x03));
      expect(
          Http3FrameType.fromValue(0x05), equals(Http3FrameType.pushPromise));
      expect(Http3FrameType.fromValue(0x03), equals(Http3FrameType.cancelPush));
    });
  });

  group('Http3Connection push promises', () {
    test('registers and checks push promises', () {
      final conn = Http3Connection(quicConnection: Object());
      final frame = Http3PushPromiseFrame(
        pushId: 42,
        encodedFieldSection: Uint8List.fromList([0xAA, 0xBB]),
      );

      expect(conn.hasPushPromise(42), isFalse);
      conn.registerPushPromise(42, frame);
      expect(conn.hasPushPromise(42), isTrue);
    });

    test('onStreamFrame with pushPromise stores promise', () {
      final conn = Http3Connection(quicConnection: Object());
      final pushFrame = Http3PushPromiseFrame(
        pushId: 99,
        encodedFieldSection: Uint8List.fromList([0x01, 0x02]),
      );
      final frame = pushFrame.toFrame();

      conn.onStreamFrame(0, frame);
      expect(conn.hasPushPromise(99), isTrue);
    });

    test('onStreamFrame with cancelPush removes promise', () {
      final conn = Http3Connection(quicConnection: Object());
      final pushFrame = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: Uint8List.fromList([0x01]),
      );
      conn.registerPushPromise(7, pushFrame);
      expect(conn.hasPushPromise(7), isTrue);

      final cancelFrame = Http3CancelPushFrame(pushId: 7);
      conn.onStreamFrame(0, cancelFrame.toFrame());
      expect(conn.hasPushPromise(7), isFalse);
    });
  });
}

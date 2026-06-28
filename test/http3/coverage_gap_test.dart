import 'dart:typed_data';

import 'package:quic_lib/src/http3/cancel_push_frame.dart';
import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/goaway_frame.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/max_push_id_frame.dart';
import 'package:quic_lib/src/http3/push_promise_frame.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';
import 'package:test/test.dart';

void main() {
  group('Http3CancelPushFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3CancelPushFrame(pushId: 7);
      final b = Http3CancelPushFrame(pushId: 7);
      final c = Http3CancelPushFrame(pushId: 8);

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
      expect(a.hashCode, isNot(equals(c.hashCode)));
    });

    test('toString contains pushId', () {
      final frame = Http3CancelPushFrame(pushId: 99);
      expect(frame.toString(), contains('99'));
      expect(frame.toString(), startsWith('Http3CancelPushFrame'));
    });

    test('edge cases: empty payload throws on parse', () {
      expect(
        () => Http3CancelPushFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('edge cases: large pushId', () {
      final frame = Http3CancelPushFrame(pushId: 4611686018427387903);
      final payload = frame.serializePayload();
      final parsed = Http3CancelPushFrame.parsePayload(payload);
      expect(parsed.pushId, equals(4611686018427387903));
      expect(parsed, equals(frame));
    });
  });

  group('Http3DataFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3DataFrame(data: [1, 2, 3]);
      final b = Http3DataFrame(data: [1, 2, 3]);
      final c = Http3DataFrame(data: [1, 2, 4]);

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString does not leak raw data', () {
      final frame = Http3DataFrame(data: [0xAB, 0xCD]);
      // SECURITY: toString must not expose raw data bytes.
      expect(frame.toString(), isNot(contains('171')));
      expect(frame.toString(), isNot(contains('205')));
      expect(frame.toString(), startsWith('Http3DataFrame'));
      expect(frame.toString(), contains('2 bytes'));
    });

    test('edge cases: empty data', () {
      final frame = Http3DataFrame.empty();
      expect(frame.data, isEmpty);
      final parsed = Http3DataFrame.fromPayload(frame.toFrame().payload);
      expect(parsed, equals(frame));
    });

    test('edge cases: large data', () {
      final large = List<int>.generate(50000, (i) => i % 256);
      final frame = Http3DataFrame(data: large);
      final parsed = Http3DataFrame.fromPayload(frame.toFrame().payload);
      expect(parsed, equals(frame));
    });
  });

  group('Http3GoawayFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3GoawayFrame(lastStreamIdOrPushId: 100);
      final b = Http3GoawayFrame(lastStreamIdOrPushId: 100);
      final c = Http3GoawayFrame(lastStreamIdOrPushId: 200);

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString contains lastStreamIdOrPushId', () {
      final frame = Http3GoawayFrame(lastStreamIdOrPushId: 42);
      expect(frame.toString(), contains('42'));
      expect(frame.toString(), startsWith('Http3GoawayFrame'));
    });

    test('edge cases: empty payload throws on parse', () {
      expect(
        () => Http3GoawayFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('edge cases: large lastStreamIdOrPushId', () {
      final frame = Http3GoawayFrame(lastStreamIdOrPushId: 4611686018427387903);
      final payload = frame.serializePayload();
      final parsed = Http3GoawayFrame.parsePayload(payload);
      expect(parsed.lastStreamIdOrPushId, equals(4611686018427387903));
      expect(parsed, equals(frame));
    });
  });

  group('Http3HeadersFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3HeadersFrame(encodedFieldSection: [1, 2, 3]);
      final b = Http3HeadersFrame(encodedFieldSection: [1, 2, 3]);
      final c = Http3HeadersFrame(encodedFieldSection: [3, 2, 1]);

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString does not leak raw encodedFieldSection', () {
      final frame = Http3HeadersFrame(encodedFieldSection: [0x01, 0x02]);
      // SECURITY: toString must not expose raw QPACK bytes.
      expect(frame.toString(), isNot(contains('[1, 2]')));
      expect(frame.toString(), startsWith('Http3HeadersFrame'));
      expect(frame.toString(), contains('2 bytes'));
    });

    test('edge cases: empty encodedFieldSection', () {
      final frame = Http3HeadersFrame(encodedFieldSection: []);
      final parsed = Http3HeadersFrame.fromPayload(frame.toFrame().payload);
      expect(parsed, equals(frame));
    });

    test('edge cases: large encodedFieldSection', () {
      final large = List<int>.generate(50000, (i) => i % 256);
      final frame = Http3HeadersFrame(encodedFieldSection: large);
      final parsed = Http3HeadersFrame.fromPayload(frame.toFrame().payload);
      expect(parsed, equals(frame));
    });
  });

  group('Http3MaxPushIdFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3MaxPushIdFrame(pushId: 5);
      final b = Http3MaxPushIdFrame(pushId: 5);
      final c = Http3MaxPushIdFrame(pushId: 6);

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString contains pushId', () {
      final frame = Http3MaxPushIdFrame(pushId: 77);
      expect(frame.toString(), contains('77'));
      expect(frame.toString(), startsWith('Http3MaxPushIdFrame'));
    });

    test('edge cases: empty payload throws on parse', () {
      expect(
        () => Http3MaxPushIdFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('edge cases: large pushId', () {
      final frame = Http3MaxPushIdFrame(pushId: 4611686018427387903);
      final payload = frame.serializePayload();
      final parsed = Http3MaxPushIdFrame.parsePayload(payload);
      expect(parsed.pushId, equals(4611686018427387903));
      expect(parsed, equals(frame));
    });
  });

  group('Http3PushPromiseFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3PushPromiseFrame(
        pushId: 1,
        encodedFieldSection: [1, 2, 3],
      );
      final b = Http3PushPromiseFrame(
        pushId: 1,
        encodedFieldSection: [1, 2, 3],
      );
      final c = Http3PushPromiseFrame(
        pushId: 2,
        encodedFieldSection: [1, 2, 3],
      );

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString contains pushId and length', () {
      final frame = Http3PushPromiseFrame(
        pushId: 3,
        encodedFieldSection: [0xAA, 0xBB],
      );
      expect(frame.toString(), contains('3'));
      expect(frame.toString(), contains('2 bytes'));
      expect(frame.toString(), startsWith('Http3PushPromiseFrame'));
    });

    test('edge cases: empty encodedFieldSection', () {
      final frame = Http3PushPromiseFrame(
        pushId: 0,
        encodedFieldSection: [],
      );
      final parsed =
          Http3PushPromiseFrame.parsePayload(frame.serializePayload());
      expect(parsed, equals(frame));
    });

    test('edge cases: large pushId and field section', () {
      final large = List<int>.generate(50000, (i) => i % 256);
      final frame = Http3PushPromiseFrame(
        pushId: 4611686018427387903,
        encodedFieldSection: large,
      );
      final parsed =
          Http3PushPromiseFrame.parsePayload(frame.serializePayload());
      expect(parsed, equals(frame));
    });
  });

  group('Http3SettingsFrame coverage gaps', () {
    test('== and hashCode', () {
      final a = Http3SettingsFrame(settings: {1: 100, 2: 200});
      final b = Http3SettingsFrame(settings: {1: 100, 2: 200});
      final c = Http3SettingsFrame(settings: {1: 100, 2: 201});

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString contains settings', () {
      final frame = Http3SettingsFrame(settings: {1: 10});
      expect(frame.toString(), contains('1'));
      expect(frame.toString(), startsWith('Http3SettingsFrame'));
    });

    test('edge cases: empty settings', () {
      final frame = Http3SettingsFrame();
      expect(frame.settings, isEmpty);
      final payload = frame.serializePayload();
      expect(payload, isEmpty);
      final parsed = Http3SettingsFrame.parsePayload(payload);
      expect(parsed, equals(frame));
    });

    test('edge cases: large values', () {
      final frame = Http3SettingsFrame(settings: {
        0x06: 4611686018427387903,
        0x01: 4611686018427387902,
      });
      final payload = frame.serializePayload();
      final parsed = Http3SettingsFrame.parsePayload(payload);
      expect(parsed, equals(frame));
    });
  });

  group('Http3FrameType coverage gaps', () {
    test('fromValue for all enum values', () {
      for (final type in Http3FrameType.values) {
        expect(Http3FrameType.fromValue(type.value), equals(type));
      }
    });

    test('fromValue with unknown value returns null', () {
      expect(Http3FrameType.fromValue(0xFF), isNull);
      expect(Http3FrameType.fromValue(0x9999), isNull);
    });
  });

  group('Http3Frame coverage gaps', () {
    test('serialize for each frame type', () {
      for (final type in Http3FrameType.values) {
        final frame = Http3Frame(
          type: type,
          payload: Uint8List.fromList([0xAB]),
        );
        final bytes = frame.serialize();
        expect(bytes.length, greaterThanOrEqualTo(2));
      }
    });

    test('parse for each frame type', () {
      for (final type in Http3FrameType.values) {
        final frame = Http3Frame(
          type: type,
          payload: Uint8List.fromList([0xCD]),
        );
        final bytes = frame.serialize();
        final (parsed, consumed) = Http3Frame.parse(bytes);
        expect(consumed, equals(bytes.length));
        expect(parsed.type, equals(type));
        expect(parsed.payload, equals(frame.payload));
      }
    });

    test('equality and hashCode', () {
      final a = Http3Frame(
        type: Http3FrameType.data,
        payload: [1, 2, 3],
      );
      final b = Http3Frame(
        type: Http3FrameType.data,
        payload: [1, 2, 3],
      );
      final c = Http3Frame(
        type: Http3FrameType.headers,
        payload: [1, 2, 3],
      );

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });
  });

  group('CapsuleType coverage gaps', () {
    test('fromValue for all values', () {
      for (final type in CapsuleType.values) {
        expect(CapsuleType.fromValue(type.value), equals(type));
      }
    });

    test('fromValue with unknown value returns null', () {
      expect(CapsuleType.fromValue(0x9999), isNull);
      expect(CapsuleType.fromValue(0x00), isNull);
    });
  });

  group('Capsule coverage gaps', () {
    test('serialize for each type', () {
      for (final type in CapsuleType.values) {
        final capsule = Capsule(
          type: type,
          payload: Uint8List.fromList([0x01]),
        );
        final bytes = capsule.serialize();
        expect(bytes.length, greaterThanOrEqualTo(2));
      }
    });

    test('parse with offset > 0', () {
      final capsule = Capsule(
        type: CapsuleType.grease1,
        payload: Uint8List.fromList([0xAA, 0xBB]),
      );
      final raw = capsule.serialize();
      final prefixed = Uint8List.fromList([0xFF, 0xFF, ...raw]);
      final (parsed, consumed) = Capsule.parse(prefixed, offset: 2);
      expect(consumed, equals(raw.length));
      expect(parsed.type, equals(CapsuleType.grease1));
      expect(parsed.payload, equals(capsule.payload));
    });

    test('parse with truncated buffer throws', () {
      final bytes = Uint8List.fromList([
        0x1b, // type = 0x1b (1-byte varint)
        0x05, // length = 5
        0x01, // only 1 payload byte
      ]);
      expect(() => Capsule.parse(bytes), throwsArgumentError);
    });

    test('equality and hashCode', () {
      final a = Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: [1, 2, 3],
      );
      final b = Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: [1, 2, 3],
      );
      final c = Capsule(
        type: CapsuleType.drainWebTransportSession,
        payload: [1, 2, 3],
      );

      expect(a == b, isTrue);
      expect(a == c, isFalse);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('toString contains type name and length', () {
      final capsule = Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: [0x01, 0x02],
      );
      expect(capsule.toString(), contains('closeWebTransportSession'));
      expect(capsule.toString(), contains('2 bytes'));
    });

    test('large payload', () {
      final large = Uint8List.fromList(
        List<int>.generate(50000, (i) => i % 256),
      );
      final capsule = Capsule(
        type: CapsuleType.drainWebTransportSession,
        payload: large,
      );
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);
      expect(consumed, equals(bytes.length));
      expect(parsed.payload, equals(large));
      expect(parsed, equals(capsule));
    });
  });

  group('WebTransportSession coverage gaps', () {
    test('initiateClose with reason phrase', () {
      final session = WebTransportSession(42);
      final capsule = session.initiateClose(
        errorCode: 1,
        reasonPhrase: 'test reason',
      );
      expect(capsule.type, equals(CapsuleType.closeWebTransportSession));
      expect(capsule.payload.length, greaterThan(1));
    });

    test('initiateClose with error code only', () {
      final session = WebTransportSession(42);
      final capsule = session.initiateClose(errorCode: 123);
      expect(capsule.type, equals(CapsuleType.closeWebTransportSession));
      expect(capsule.payload, isNotEmpty);
    });

    test('onCapsuleReceived with unknown capsule type is ignored', () {
      final session = WebTransportSession(1);
      session.onCapsuleReceived(Capsule(
        type: CapsuleType.grease0,
        payload: [0x01],
      ));
      expect(session.isActive, isTrue);
      expect(session.isClosed, isFalse);
      expect(session.isDraining, isFalse);
    });

    test('onCloseAcknowledged when already closed', () {
      final session = WebTransportSession(1);
      session.onCloseAcknowledged();
      expect(session.isClosed, isTrue);
      // calling again should not throw
      session.onCloseAcknowledged();
      expect(session.isClosed, isTrue);
    });

    test('sessionId getter', () {
      final session = WebTransportSession(12345);
      expect(session.sessionId, equals(12345));
    });
  });
}

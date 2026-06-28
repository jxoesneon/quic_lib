import 'dart:typed_data';

import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/goaway_frame.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/max_push_id_frame.dart';
import 'package:quic_lib/src/http3/push_promise_frame.dart';
import 'package:test/test.dart';

void main() {
  group('Http3MaxPushIdFrame', () {
    test('parsePayload empty throws', () {
      expect(
        () => Http3MaxPushIdFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('toString', () {
      final frame = Http3MaxPushIdFrame(pushId: 42);
      expect(frame.toString(), 'Http3MaxPushIdFrame(pushId: 42)');
    });

    test('equality and hashCode', () {
      final a = Http3MaxPushIdFrame(pushId: 7);
      final b = Http3MaxPushIdFrame(pushId: 7);
      final c = Http3MaxPushIdFrame(pushId: 8);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c));
    });
  });

  group('Http3GoawayFrame', () {
    test('parsePayload empty throws', () {
      expect(
        () => Http3GoawayFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('toString', () {
      final frame = Http3GoawayFrame(lastStreamIdOrPushId: 99);
      expect(frame.toString(), 'Http3GoawayFrame(lastStreamIdOrPushId: 99)');
    });

    test('equality and hashCode', () {
      final a = Http3GoawayFrame(lastStreamIdOrPushId: 7);
      final b = Http3GoawayFrame(lastStreamIdOrPushId: 7);
      final c = Http3GoawayFrame(lastStreamIdOrPushId: 8);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c));
    });
  });

  group('Http3PushPromiseFrame', () {
    test('parse alias works', () {
      final payload = Uint8List.fromList([0x01, 0xAB, 0xCD]);
      final frame = Http3PushPromiseFrame.parse(payload);
      expect(frame.pushId, 1);
      expect(frame.encodedFieldSection, [0xAB, 0xCD]);
    });

    test('parsePayload empty throws', () {
      expect(
        () => Http3PushPromiseFrame.parsePayload(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('toString', () {
      final frame = Http3PushPromiseFrame(
        pushId: 5,
        encodedFieldSection: [1, 2, 3],
      );
      expect(frame.toString(),
          'Http3PushPromiseFrame(pushId: 5, encodedFieldSection: 3 bytes)');
    });

    test('equality and hashCode', () {
      final a = Http3PushPromiseFrame(pushId: 1, encodedFieldSection: [2, 3]);
      final b = Http3PushPromiseFrame(pushId: 1, encodedFieldSection: [2, 3]);
      final c = Http3PushPromiseFrame(pushId: 1, encodedFieldSection: [2, 4]);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c));
    });
  });

  group('Http3HeadersFrame', () {
    test('equality and hashCode', () {
      final a = Http3HeadersFrame(encodedFieldSection: [1, 2]);
      final b = Http3HeadersFrame(encodedFieldSection: [1, 2]);
      final c = Http3HeadersFrame(encodedFieldSection: [1, 3]);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c));
    });

    test('toString', () {
      final frame = Http3HeadersFrame(encodedFieldSection: [1, 2, 3]);
      expect(frame.toString(), 'Http3HeadersFrame(3 bytes)');
    });
  });

  group('Http3DataFrame', () {
    test('empty factory', () {
      final frame = Http3DataFrame.empty();
      expect(frame.data, isEmpty);
    });

    test('equality and hashCode', () {
      final a = Http3DataFrame(data: [1, 2]);
      final b = Http3DataFrame(data: [1, 2]);
      final c = Http3DataFrame(data: [1, 3]);
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c));
    });

    test('toString', () {
      final frame = Http3DataFrame(data: [1, 2, 3]);
      expect(frame.toString(), 'Http3DataFrame(3 bytes)');
    });
  });
}

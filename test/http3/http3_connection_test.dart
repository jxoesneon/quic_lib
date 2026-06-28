import 'dart:typed_data';

import 'package:quic_lib/src/http3/cancel_push_frame.dart';
import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/goaway_frame.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/extended_connect_request.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_request.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:quic_lib/src/http3/origin_frame.dart';
import 'package:quic_lib/src/http3/priority_update_frame.dart';
import 'package:quic_lib/src/http3/push_promise_frame.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/streams/round_robin_scheduler.dart';
import 'package:test/test.dart';

class FakeQuicConnection {
  int _nextBidiStreamId = 0;
  int _nextUniStreamId = 2;

  int openBidirectionalStream() {
    final id = _nextBidiStreamId;
    _nextBidiStreamId += 4;
    return id;
  }

  int openUnidirectionalStream() {
    final id = _nextUniStreamId;
    _nextUniStreamId += 4;
    return id;
  }

  List<int>? get connectionId => [0xAB, 0xCD];

  Future<Uint8List> buildEncryptedPacket({
    required space,
    required List<dynamic> frames,
    required List<int> dcid,
  }) async {
    return Uint8List.fromList([0xFF, 0xFF]);
  }
}

void main() {
  group('Http3Connection', () {
    test('default localSettings', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(
        conn.localSettings.settings[Http3SettingsId.maxFieldSectionSize.value],
        equals(16384),
      );
    });

    test('custom localSettings', () {
      final settings = Http3SettingsFrame.from(maxFieldSectionSize: 8192);
      final conn = Http3Connection(
        quicConnection: Object(),
        localSettings: settings,
      );
      expect(
        conn.localSettings.settings[Http3SettingsId.maxFieldSectionSize.value],
        equals(8192),
      );
    });

    test('sendRequest returns a stream ID', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(method: 'GET', path: '/');
      final streamId = await conn.sendRequest(request);
      expect(streamId, equals(0));
    });

    test('sendRequest with body sends data frames', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(
        method: 'POST',
        path: '/upload',
        body: Uint8List.fromList([1, 2, 3]),
      );
      final streamId = await conn.sendRequest(request);
      expect(streamId, equals(0));
      expect(conn.hasBody(streamId), isTrue);
    });

    test('sendRequest with empty body does not send data', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(
        method: 'POST',
        path: '/upload',
        body: Uint8List(0),
      );
      final streamId = await conn.sendRequest(request);
      expect(conn.hasBody(streamId), isFalse);
    });

    test('sendExtendedConnect returns a stream ID', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = ExtendedConnectRequest(
        protocol: 'webtransport',
        authority: 'example.com',
        path: '/',
      );
      final streamId = await conn.sendExtendedConnect(request);
      expect(streamId, equals(0));
    });

    test('sendExtendedConnect stages headers and body', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = ExtendedConnectRequest(
        protocol: 'webtransport',
        authority: 'example.com',
        path: '/wt',
        body: Uint8List.fromList([1, 2]),
      );
      final streamId = await conn.sendExtendedConnect(request);
      expect(conn.getPendingHeaders(streamId), isNotNull);
      expect(conn.hasBody(streamId), isTrue);
    });

    test('sendSettings creates pending settings', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.pendingSettings, isNull);
      final settings = conn.sendSettings();
      expect(conn.pendingSettings, isNotNull);
      expect(
        settings.settings[Http3SettingsId.maxFieldSectionSize.value],
        equals(65536),
      );
    });

    test('onSettingsReceived updates peer settings', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.settingsExchanged, isFalse);
      final settings = Http3SettingsFrame.from(maxFieldSectionSize: 4096);
      conn.onSettingsReceived(settings);
      expect(conn.settingsExchanged, isTrue);
      expect(
        conn.peerSettings.settings[Http3SettingsId.maxFieldSectionSize.value],
        equals(4096),
      );
    });

    test('isConnectProtocolEnabled is true when peer sets it', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.isConnectProtocolEnabled, isFalse);
      conn.onSettingsReceived(
        Http3SettingsFrame.from(enableConnectProtocol: 1),
      );
      expect(conn.isConnectProtocolEnabled, isTrue);
    });

    test('isH3DatagramEnabled is true when peer sets it', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.isH3DatagramEnabled, isFalse);
      conn.onSettingsReceived(
        Http3SettingsFrame.from(h3Datagram: 1),
      );
      expect(conn.isH3DatagramEnabled, isTrue);
    });

    test('sendBody with empty data creates EOF marker', () async {
      final conn = Http3Connection(quicConnection: Object());
      await conn.sendBody(4, Uint8List(0));
      expect(conn.hasBody(4), isTrue);
      final body = conn.getBody(4);
      expect(body, isNotNull);
      expect(body!.length, equals(0));
    });

    test('sendBody with small data stores single frame', () async {
      final conn = Http3Connection(quicConnection: Object());
      final data = Uint8List.fromList([1, 2, 3, 4]);
      await conn.sendBody(4, data);
      expect(conn.hasBody(4), isTrue);
      final pending = conn.getPendingData(4);
      expect(pending.length, equals(1));
    });

    test('sendBody chunks large data into 4096-byte frames', () async {
      final conn = Http3Connection(quicConnection: Object());
      final data = Uint8List(10000);
      await conn.sendBody(4, data);
      final pending = conn.getPendingData(4);
      expect(pending.length, equals(3)); // 4096 + 4096 + 1808
    });

    test('getBody returns null when no data exists', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.getBody(4), isNull);
    });

    test('getBody concatenates non-empty frames', () async {
      final conn = Http3Connection(quicConnection: Object());
      await conn.sendBody(4, Uint8List.fromList([1, 2, 3]));
      await conn.sendBody(4, Uint8List.fromList([4, 5]));
      final body = conn.getBody(4);
      expect(body, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
    });

    test('getBody ignores EOF marker frames', () async {
      final conn = Http3Connection(quicConnection: Object());
      await conn.sendBody(4, Uint8List(0));
      final body = conn.getBody(4);
      expect(body, isNotNull);
      expect(body!.length, equals(0));
    });

    test('hasBody returns false for unknown stream', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.hasBody(99), isFalse);
    });

    test('hasBody returns false after empty sendRequest', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(method: 'GET', path: '/');
      final streamId = await conn.sendRequest(request);
      expect(conn.hasBody(streamId), isFalse);
    });

    test('getPendingHeaders returns null for unknown stream', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.getPendingHeaders(99), isNull);
    });

    test('getPendingData returns empty list for unknown stream', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.getPendingData(99), isEmpty);
    });

    test('onStreamFrame with SETTINGS calls onSettingsReceived', () {
      final conn = Http3Connection(quicConnection: Object());
      final settings = Http3SettingsFrame.from(maxFieldSectionSize: 2048);
      final frame = Http3Frame(
        type: Http3FrameType.settings,
        payload: settings.serializePayload(),
      );
      conn.onStreamFrame(0, frame);
      expect(conn.settingsExchanged, isTrue);
      expect(conn.peerSettings, equals(settings));
    });

    test('onStreamFrame with HEADERS stores headers', () {
      final conn = Http3Connection(quicConnection: Object());
      final headers = Http3HeadersFrame(encodedFieldSection: [0x01, 0x02]);
      final frame = headers.toFrame();
      conn.onStreamFrame(4, frame);
      final pending = conn.getPendingHeaders(4);
      expect(pending, isNotNull);
      expect(pending, equals(headers));
      expect(conn.lastAcceptedStreamId, equals(4));
    });

    test('onStreamFrame with DATA stores data frames', () {
      final conn = Http3Connection(quicConnection: Object());
      final data = Http3DataFrame(data: [0x03, 0x04]);
      final frame = data.toFrame();
      conn.onStreamFrame(4, frame);
      final pending = conn.getPendingData(4);
      expect(pending, hasLength(1));
      expect(pending.first, equals(data));
      expect(conn.lastAcceptedStreamId, equals(4));
    });

    test('onStreamFrame with GOAWAY sets isClosing', () {
      final conn = Http3Connection(quicConnection: Object());
      final frame = Http3Frame(type: Http3FrameType.goaway, payload: []);
      conn.onStreamFrame(0, frame);
      expect(conn.isClosing, isTrue);
    });

    test('onStreamFrame with PUSH_PROMISE registers promise', () {
      final conn = Http3Connection(quicConnection: Object());
      final pushFrame = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: [0x01, 0x02],
      );
      final frame = pushFrame.toFrame();
      conn.onStreamFrame(4, frame);
      expect(conn.hasPushPromise(7), isTrue);
    });

    test('onStreamFrame with CANCEL_PUSH removes promise', () {
      final conn = Http3Connection(quicConnection: Object());
      final pushFrame = Http3PushPromiseFrame(
        pushId: 7,
        encodedFieldSection: [0x01, 0x02],
      );
      conn.registerPushPromise(7, pushFrame);
      expect(conn.hasPushPromise(7), isTrue);

      final cancelFrame = Http3CancelPushFrame(pushId: 7);
      final frame = cancelFrame.toFrame();
      conn.onStreamFrame(0, frame);
      expect(conn.hasPushPromise(7), isFalse);
    });

    test('onStreamFrame with unknown type is no-op', () {
      final conn = Http3Connection(quicConnection: Object());
      final frame = Http3Frame(type: Http3FrameType.reserved, payload: [0x00]);
      // Should not throw
      conn.onStreamFrame(0, frame);
      expect(conn.isClosing, isFalse);
    });

    test('getResponse decodes pending headers', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final response = Http3Response(
          statusCode: 200, headers: {'content-type': 'text/plain'});
      final encoded = response.encodeHeaders();

      final frame = Http3Frame(
        type: Http3FrameType.headers,
        payload: encoded,
      );
      conn.onStreamFrame(4, frame);
      final decoded = conn.getResponse(4);
      expect(decoded, isNotNull);
      expect(decoded!.statusCode, equals(200));
    });

    test('getResponse returns null when no headers', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.getResponse(4), isNull);
    });

    test('registerPushPromise and hasPushPromise', () {
      final conn = Http3Connection(quicConnection: Object());
      final frame = Http3PushPromiseFrame(
        pushId: 42,
        encodedFieldSection: [0x01],
      );
      expect(conn.hasPushPromise(42), isFalse);
      conn.registerPushPromise(42, frame);
      expect(conn.hasPushPromise(42), isTrue);
    });

    test('close sets isClosing and hasSentGoaway', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.hasSentGoaway, isFalse);
      conn.close();
      expect(conn.isClosing, isTrue);
      expect(conn.hasSentGoaway, isTrue);
      expect(conn.sentGoawayFrames, hasLength(1));
    });

    test('close with previous stream activity uses lastAcceptedStreamId', () {
      final conn = Http3Connection(quicConnection: Object());
      final data = Http3DataFrame(data: [0x01]);
      conn.onStreamFrame(8, data.toFrame());
      conn.close();
      expect(conn.sentGoawayFrames.first.lastStreamIdOrPushId, equals(8));
    });

    test('pendingQuicPackets accumulates after close with build-capable quic',
        () async {
      final fakeQuic = FakeQuicConnection();
      final conn = Http3Connection(quicConnection: fakeQuic);
      conn.close();
      // Give the async _sendGoawayFrame a moment
      await Future.delayed(Duration(milliseconds: 10));
      expect(conn.pendingQuicPackets, isNotEmpty);
    });

    test('quicConnection getter returns the underlying connection', () {
      final fakeQuic = Object();
      final conn = Http3Connection(quicConnection: fakeQuic);
      expect(conn.quicConnection, same(fakeQuic));
    });

    test('Http3Stream can be constructed', () {
      final stream = Http3Stream(42);
      expect(stream.streamId, equals(42));
    });

    test('lastAcceptedStreamId tracks highest seen stream', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.lastAcceptedStreamId, equals(0));
      conn.onStreamFrame(
          4, Http3Frame(type: Http3FrameType.data, payload: [0x01]));
      expect(conn.lastAcceptedStreamId, equals(4));
      conn.onStreamFrame(
          8, Http3Frame(type: Http3FrameType.headers, payload: [0x01]));
      expect(conn.lastAcceptedStreamId, equals(8));
      // Lower stream ID should not decrease lastAcceptedStreamId
      conn.onStreamFrame(
          2, Http3Frame(type: Http3FrameType.data, payload: [0x01]));
      expect(conn.lastAcceptedStreamId, equals(8));
    });

    test('onOriginFrameReceived stores origins', () {
      final conn = Http3Connection(quicConnection: Object());
      final originFrame = OriginFrame(
        origins: ['https://example.com', 'https://example.org'],
      );
      conn.onOriginFrameReceived(originFrame);
      expect(
        conn.alternativeOrigins,
        equals(['https://example.com', 'https://example.org']),
      );
    });

    test('onStreamFrame with ORIGIN stores origins', () {
      final conn = Http3Connection(quicConnection: Object());
      final originFrame = OriginFrame(origins: ['https://foo.bar']);
      conn.onStreamFrame(0, originFrame.toFrame());
      expect(conn.alternativeOrigins, equals(['https://foo.bar']));
    });

    test('sendPriorityUpdate stages frame and packet', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.pendingPriorityUpdates, isEmpty);
      conn.sendPriorityUpdate(42, 'u=3, i');
      expect(conn.pendingPriorityUpdates, hasLength(1));
      expect(conn.pendingPriorityUpdates.first.streamId, equals(42));
      expect(conn.pendingPriorityUpdates.first.priorityFieldValue, equals('u=3, i'));
      expect(conn.pendingQuicPackets, isNotEmpty);
    });

    test('onStreamFrame with PRIORITY_UPDATE stores update', () {
      final conn = Http3Connection(quicConnection: Object());
      final priorityFrame = PriorityUpdateFrame(
        streamId: 7,
        priorityFieldValue: 'u=0',
      );
      conn.onStreamFrame(0, priorityFrame.toFrame());
      expect(conn.pendingPriorityUpdates, hasLength(1));
      expect(conn.pendingPriorityUpdates.first.streamId, equals(7));
    });

    test('onStreamFrame with PRIORITY_UPDATE_PUSH stores update', () {
      final conn = Http3Connection(quicConnection: Object());
      final pushFrame = PriorityUpdatePushFrame(
        streamId: 3,
        priorityFieldValue: 'u=6',
      );
      conn.onStreamFrame(0, pushFrame.toFrame());
      expect(conn.pendingPriorityUpdates, hasLength(1));
      expect(conn.pendingPriorityUpdates.first.streamId, equals(3));
      expect(
        conn.pendingPriorityUpdates.first.priorityFieldValue,
        equals('u=6'),
      );
    });

    test('streamScheduler getter and setter', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.streamScheduler, isNull);
      final scheduler = RoundRobinScheduler();
      conn.streamScheduler = scheduler;
      expect(conn.streamScheduler, same(scheduler));
    });
  });
}

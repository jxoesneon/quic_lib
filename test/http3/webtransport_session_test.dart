import 'dart:typed_data';

import 'package:quic_lib/src/http3/capsule_protocol.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/http3/webtransport_session.dart';
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
  group('WebTransportSession', () {
    test('createWebTransportSession succeeds on 2xx', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final future = conn.createWebTransportSession(
        WebTransportConnectRequest(authority: 'example.com', path: '/'),
      );

      // Inject a 200 OK response on stream 0.
      final response = Http3Response(statusCode: 200, headers: {});
      final frame = Http3Frame(
        type: Http3FrameType.headers,
        payload: response.encodeHeaders(),
      );
      conn.onStreamFrame(0, frame);

      final session = await future;
      expect(session, isNotNull);
      expect(session.sessionId, equals(0));
      expect(conn.webTransportSessions[0], same(session));
    });

    test('createWebTransportSession throws on non-2xx', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final future = conn.createWebTransportSession(
        WebTransportConnectRequest(authority: 'example.com', path: '/'),
      );

      // Inject a 400 Bad Request response.
      final response = Http3Response(statusCode: 400, headers: {});
      final frame = Http3Frame(
        type: Http3FrameType.headers,
        payload: response.encodeHeaders(),
      );
      conn.onStreamFrame(0, frame);

      expect(future, throwsA(isA<StateError>()));
    });

    test('sendDatagram stages capsule when QUIC datagrams unsupported',
        () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final future = conn.createWebTransportSession(
        WebTransportConnectRequest(authority: 'example.com', path: '/'),
      );

      // Inject a 200 OK response on stream 0.
      final response = Http3Response(statusCode: 200, headers: {});
      conn.onStreamFrame(
        0,
        Http3Frame(
          type: Http3FrameType.headers,
          payload: response.encodeHeaders(),
        ),
      );

      final session = await future;

      // Enable HTTP Datagrams via peer SETTINGS.
      conn.onSettingsReceived(
        Http3SettingsFrame.from(h3Datagram: 1),
      );

      final data = Uint8List.fromList([1, 2, 3]);
      session.sendDatagram(data);

      // The connection should have pending data for the session stream.
      expect(conn.hasBody(session.sessionId), isTrue);
    });

    test('close sends CLOSE_WEBTRANSPORT_SESSION capsule', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final future = conn.createWebTransportSession(
        WebTransportConnectRequest(authority: 'example.com', path: '/'),
      );

      // Inject a 200 OK response on stream 0.
      final response = Http3Response(statusCode: 200, headers: {});
      conn.onStreamFrame(
        0,
        Http3Frame(
          type: Http3FrameType.headers,
          payload: response.encodeHeaders(),
        ),
      );

      final session = await future;
      expect(session.isClosed, isFalse);
      session.close(errorCode: 42);
      expect(session.isClosed, isTrue);
      expect(conn.hasBody(session.sessionId), isTrue);
    });

    test('onCapsule adds datagram to stream', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);
      final data = Uint8List.fromList([0x0A, 0x0B]);

      session.datagrams.first.then((dgram) {
        expect(dgram, equals(data));
      });

      session.onCapsule(DatagramCapsule(data));
    });

    test('onCapsule with close capsule closes session', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);

      expect(session.isClosed, isFalse);
      session.onCapsule(CloseWebTransportSessionCapsule(errorCode: 7));
      expect(session.isClosed, isTrue);
    });

    test('sendStream opens a new stream', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);
      final data = Uint8List.fromList([1, 2, 3, 4]);

      session.sendStream(data);
      // Allow the microtask to complete.
      await Future<void>.delayed(Duration.zero);

      // Stream 0 should have pending data (first bidi stream).
      expect(conn.hasBody(0), isTrue);
    });

    test('session getters and flags', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 7);
      expect(session.sessionId, equals(7));
      expect(session.isClosed, isFalse);
      expect(session.isDraining, isFalse);
      expect(session.isActive, isTrue);
      expect(session.receivedGoaway, isFalse);
      expect(session.receivedDatagrams, isEmpty);
      expect(session.registeredBidirectionalStreams, isEmpty);
      expect(session.registeredUnidirectionalStreams, isEmpty);
    });

    test('sendDatagram and sendStream throw when session is closed', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);
      session.close();
      expect(() => session.sendDatagram(Uint8List(1)), throwsStateError);
      expect(() => session.sendStream(Uint8List(1)), throwsStateError);
    });

    test('close is idempotent', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);
      session.close(errorCode: 1);
      expect(session.isClosed, isTrue);
      session.close(errorCode: 2);
      expect(session.isClosed, isTrue);
    });

    test('onCapsule with unknown type is ignored', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final session = WebTransportSession(conn, 0);
      expect(session.isClosed, isFalse);
      session.onCapsule(UnknownCapsule(0xFF, Uint8List(1)));
      expect(session.isClosed, isFalse);
    });
  });
}

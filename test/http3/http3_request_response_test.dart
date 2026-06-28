import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_request.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:test/test.dart';

class FakeQuicConnection {
  int _nextStreamId = 0;
  int openBidirectionalStream() {
    final id = _nextStreamId;
    _nextStreamId += 4;
    return id;
  }
}

void main() {
  group('Http3Request', () {
    test('encode and decode a simple GET request', () {
      final request = Http3Request(
        method: 'GET',
        path: '/',
        headers: {'host': 'example.com'},
      );
      final encoded = request.encodeHeaders();
      expect(encoded.isNotEmpty, isTrue);

      final decoded = Http3Request.decodeHeaders(encoded);
      expect(decoded.method, equals('GET'));
      expect(decoded.path, equals('/'));
      expect(decoded.headers['host'], equals('example.com'));
    });

    test('encode and decode a POST request with body', () {
      final body =
          Uint8List.fromList([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
      final request = Http3Request(
        method: 'POST',
        path: '/upload',
        headers: {
          'host': 'example.com',
          'content-type': 'application/json',
        },
        body: body,
      );
      final encoded = request.encodeHeaders();
      expect(encoded.isNotEmpty, isTrue);

      final decoded = Http3Request.decodeHeaders(encoded);
      expect(decoded.method, equals('POST'));
      expect(decoded.path, equals('/upload'));
      expect(decoded.headers['host'], equals('example.com'));
      expect(decoded.headers['content-type'], equals('application/json'));
    });
  });

  group('Http3Response', () {
    test('encode and decode a 200 OK response', () {
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/plain'},
      );
      final encoded = response.encodeHeaders();
      expect(encoded.isNotEmpty, isTrue);

      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(200));
      expect(decoded.headers['content-type'], equals('text/plain'));
    });
  });

  group('Http3Connection with request/response', () {
    test('sendRequest with Http3Request returns stream ID', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(
        method: 'GET',
        path: '/',
        headers: {'host': 'example.com'},
      );
      final streamId = await conn.sendRequest(request);
      expect(streamId, equals(0));
    });

    test(
        'getResponse returns decoded response after onStreamFrame with HEADERS',
        () {
      final conn = Http3Connection(quicConnection: Object());
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/html'},
      );
      final encoded = response.encodeHeaders();
      final headersFrame = Http3HeadersFrame(encodedFieldSection: encoded);
      final frame = headersFrame.toFrame();
      conn.onStreamFrame(4, frame);

      final decoded = conn.getResponse(4);
      expect(decoded, isNotNull);
      expect(decoded!.statusCode, equals(200));
      expect(decoded.headers['content-type'], equals('text/html'));
    });

    test('getResponse returns null when no headers received', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.getResponse(4), isNull);
    });
  });
}

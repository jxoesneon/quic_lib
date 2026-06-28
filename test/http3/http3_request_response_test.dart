import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_request.dart';
import 'package:quic_lib/src/http3/http3_response.dart';
import 'package:quic_lib/src/http3/qpack_encoder.dart';
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

    test('encode and decode response with empty headers', () {
      final response = Http3Response(
        statusCode: 404,
        headers: {},
      );
      final encoded = response.encodeHeaders();
      expect(encoded.isNotEmpty, isTrue);

      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(404));
      expect(decoded.headers, isEmpty);
    });

    test('decode response with no :status falls back to 0', () {
      // Encode only a non-status header so :status is missing
      final encoded = QpackEncoder.encodeFieldLines([
        (name: 'content-type', value: 'text/html'),
      ]);
      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(0));
      expect(decoded.headers['content-type'], equals('text/html'));
    });

    test('decode response with invalid :status falls back to 0', () {
      final encoded = QpackEncoder.encodeFieldLines([
        (name: ':status', value: 'not-a-number'),
        (name: 'server', value: 'test'),
      ]);
      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(0));
      expect(decoded.headers['server'], equals('test'));
    });

    test('toString includes status and headers', () {
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/plain'},
      );
      expect(response.toString(), contains('200'));
      expect(response.toString(), contains('text/plain'));
    });

    test('response with body field does not affect headers encoding', () {
      final body = Uint8List.fromList([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      final response = Http3Response(
        statusCode: 200,
        headers: {'content-type': 'text/plain'},
        body: body,
      );
      final encoded = response.encodeHeaders();
      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(200));
      expect(decoded.headers['content-type'], equals('text/plain'));
      expect(decoded.body, isNull);
    });

    test('encodeHeaders lowercases header names', () {
      final response = Http3Response(
        statusCode: 200,
        headers: {'Content-Type': 'text/plain', 'X-Custom': 'value'},
      );
      final encoded = response.encodeHeaders();
      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.headers['content-type'], equals('text/plain'));
      expect(decoded.headers['x-custom'], equals('value'));
    });

    test('decode preserves multiple headers', () {
      final response = Http3Response(
        statusCode: 302,
        headers: {
          'location': '/redirect',
          'cache-control': 'no-cache',
          'set-cookie': 'session=abc',
        },
      );
      final encoded = response.encodeHeaders();
      final decoded = Http3Response.decodeHeaders(encoded);
      expect(decoded.statusCode, equals(302));
      expect(decoded.headers['location'], equals('/redirect'));
      expect(decoded.headers['cache-control'], equals('no-cache'));
      expect(decoded.headers['set-cookie'], equals('session=abc'));
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

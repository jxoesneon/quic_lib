import 'package:quic_lib/src/http3/http3_stream.dart';
import 'package:test/test.dart';

void main() {
  group('Http3StreamHandler.typeFromStreamId', () {
    test('detects client control stream correctly', () {
      expect(
        Http3StreamHandler.typeFromStreamId(0x00, false),
        equals(Http3StreamType.control),
      );
    });

    test('detects server control stream correctly', () {
      expect(
        Http3StreamHandler.typeFromStreamId(0x01, true),
        equals(Http3StreamType.control),
      );
    });

    test('detects request stream correctly', () {
      // Client-initiated bidirectional streams (type bits = 0x00)
      expect(
        Http3StreamHandler.typeFromStreamId(0x04, false),
        equals(Http3StreamType.request),
      );
      expect(
        Http3StreamHandler.typeFromStreamId(0x08, false),
        equals(Http3StreamType.request),
      );
    });

    test('detects push stream correctly', () {
      // Server-initiated unidirectional streams (type bits = 0x03)
      expect(
        Http3StreamHandler.typeFromStreamId(0x03, false),
        equals(Http3StreamType.push),
      );
      expect(
        Http3StreamHandler.typeFromStreamId(0x07, true),
        equals(Http3StreamType.push),
      );
      expect(
        Http3StreamHandler.typeFromStreamId(0x0B, false),
        equals(Http3StreamType.push),
      );
    });

    test('returns reserved for unknown/unused stream types', () {
      // 0x02: client-initiated unidirectional — not used in HTTP/3 per spec
      expect(
        Http3StreamHandler.typeFromStreamId(0x02, false),
        equals(Http3StreamType.reserved),
      );
      // 0x01 from client perspective: server-initiated bidirectional — not used
      expect(
        Http3StreamHandler.typeFromStreamId(0x01, false),
        equals(Http3StreamType.reserved),
      );
      // 0x00 from server perspective: client-initiated bidirectional — request
      expect(
        Http3StreamHandler.typeFromStreamId(0x00, true),
        equals(Http3StreamType.request),
      );
    });
  });

  group('Http3StreamHandler instance getters', () {
    test('client control stream getter', () {
      final handler = Http3StreamHandler(0x00, isServer: false);
      expect(handler.isControlStream, isTrue);
      expect(handler.isRequestStream, isFalse);
      expect(handler.isPushStream, isFalse);
    });

    test('server control stream getter', () {
      final handler = Http3StreamHandler(0x01, isServer: true);
      expect(handler.isControlStream, isTrue);
      expect(handler.isRequestStream, isFalse);
      expect(handler.isPushStream, isFalse);
    });

    test('request stream getter', () {
      final handler = Http3StreamHandler(0x04, isServer: false);
      expect(handler.isControlStream, isFalse);
      expect(handler.isRequestStream, isTrue);
      expect(handler.isPushStream, isFalse);
    });

    test('push stream getter', () {
      final handler = Http3StreamHandler(0x03, isServer: false);
      expect(handler.isControlStream, isFalse);
      expect(handler.isRequestStream, isFalse);
      expect(handler.isPushStream, isTrue);
    });
  });
}

import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:dart_quic/src/http3/goaway_frame.dart';
import 'package:dart_quic/src/http3/headers_frame.dart';
import 'package:dart_quic/src/http3/http3_connection.dart';
import 'package:test/test.dart';

void main() {
  group('Http3Connection GOAWAY sending', () {
    test('close() sets isClosing to true', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.isClosing, isFalse);
      conn.close();
      expect(conn.isClosing, isTrue);
    });

    test('close() records a GOAWAY frame', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.sentGoawayFrames, isEmpty);
      conn.close();
      expect(conn.sentGoawayFrames, hasLength(1));
      expect(conn.sentGoawayFrames.first, isA<Http3GoawayFrame>());
    });

    test('hasSentGoaway is true after close', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.hasSentGoaway, isFalse);
      conn.close();
      expect(conn.hasSentGoaway, isTrue);
    });

    test('lastAcceptedStreamId tracks the highest stream ID', () {
      final conn = Http3Connection(quicConnection: Object());
      expect(conn.lastAcceptedStreamId, equals(0));

      final headers1 = Http3HeadersFrame(encodedFieldSection: [0x01]);
      conn.onStreamFrame(4, headers1.toFrame());
      expect(conn.lastAcceptedStreamId, equals(4));

      final headers2 = Http3HeadersFrame(encodedFieldSection: [0x02]);
      conn.onStreamFrame(8, headers2.toFrame());
      expect(conn.lastAcceptedStreamId, equals(8));

      // Lower stream ID should not update the maximum
      final headers3 = Http3HeadersFrame(encodedFieldSection: [0x03]);
      conn.onStreamFrame(4, headers3.toFrame());
      expect(conn.lastAcceptedStreamId, equals(8));
    });

    test('GOAWAY frame streamId matches lastAcceptedStreamId', () {
      final conn = Http3Connection(quicConnection: Object());

      final headers = Http3HeadersFrame(encodedFieldSection: [0x01]);
      conn.onStreamFrame(12, headers.toFrame());
      expect(conn.lastAcceptedStreamId, equals(12));

      conn.close();
      expect(conn.sentGoawayFrames, hasLength(1));
      expect(
        conn.sentGoawayFrames.first.lastStreamIdOrPushId,
        equals(conn.lastAcceptedStreamId),
      );
    });

    test('DATA frames also update lastAcceptedStreamId', () {
      final conn = Http3Connection(quicConnection: Object());
      final dataFrame = Http3Frame(
        type: Http3FrameType.data,
        payload: [0xAB, 0xCD],
      );
      conn.onStreamFrame(20, dataFrame);
      expect(conn.lastAcceptedStreamId, equals(20));
    });
  });
}

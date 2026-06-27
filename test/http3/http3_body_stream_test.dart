import 'dart:typed_data';

import 'package:dart_quic/src/http3/data_frame.dart';
import 'package:dart_quic/src/http3/http3_body_stream.dart';
import 'package:dart_quic/src/http3/http3_connection.dart';
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
  group('Http3Connection body streaming', () {
    test('sendBody stores DATA frames', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final body = Uint8List.fromList(List.generate(5000, (i) => i % 256));
      await conn.sendBody(0, body);

      expect(conn.hasBody(0), isTrue);
      final pending = conn.getPendingData(0);
      expect(pending.length, greaterThan(1));
      expect(pending.first, isA<Http3DataFrame>());
    });

    test('sendBody with empty body stores an empty EOF marker frame', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      await conn.sendBody(0, Uint8List(0));

      expect(conn.hasBody(0), isTrue);
      final pending = conn.getPendingData(0);
      expect(pending, hasLength(1));
      expect(pending.first.data, isEmpty);
    });

    test('getBody concatenates frames', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final chunk1 = Uint8List.fromList([0x01, 0x02]);
      final chunk2 = Uint8List.fromList([0x03, 0x04, 0x05]);
      await conn.sendBody(4, chunk1);
      await conn.sendBody(4, chunk2);

      final body = conn.getBody(4);
      expect(body, isNotNull);
      expect(body, equals(Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05])));
    });

    test('getBody excludes empty EOF-marker frames', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final chunk = Uint8List.fromList([0xAA, 0xBB]);
      await conn.sendBody(8, chunk);
      await conn.sendBody(8, Uint8List(0));

      final body = conn.getBody(8);
      expect(body, equals(chunk));
    });

    test('hasBody returns false when no data exists', () {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      expect(conn.hasBody(99), isFalse);
    });
  });

  group('Http3BodyStream', () {
    test('yields chunks as they arrive', () async {
      final stream = Http3BodyStream();

      // Start collecting before frames are added.
      final futureChunks = stream.chunks.toList();

      stream.addFrame(Http3DataFrame(data: [0x01, 0x02]));
      stream.addFrame(Http3DataFrame(data: [0x03]));
      stream.addFrame(Http3DataFrame.empty()); // EOF

      final received = await futureChunks;

      expect(received.length, equals(2));
      expect(received[0], equals(Uint8List.fromList([0x01, 0x02])));
      expect(received[1], equals(Uint8List.fromList([0x03])));
    });

    test('fullBody concatenates all chunks', () async {
      final stream = Http3BodyStream();

      stream.addFrame(Http3DataFrame(data: [0x0A, 0x0B]));
      stream.addFrame(Http3DataFrame(data: [0x0C, 0x0D, 0x0E]));
      stream.addFrame(Http3DataFrame.empty()); // EOF

      final body = await stream.fullBody;
      expect(body, equals(Uint8List.fromList([0x0A, 0x0B, 0x0C, 0x0D, 0x0E])));
    });

    test('isComplete is true after EOF marker', () {
      final stream = Http3BodyStream();
      expect(stream.isComplete, isFalse);
      stream.addFrame(Http3DataFrame.empty());
      expect(stream.isComplete, isTrue);
    });

    test('addFrame after EOF is ignored', () {
      final stream = Http3BodyStream();
      stream.addFrame(Http3DataFrame.empty());
      stream.addFrame(Http3DataFrame(data: [0xFF]));
      expect(stream.isComplete, isTrue);
    });
  });
}

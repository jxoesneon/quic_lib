import 'package:quic_lib/src/http3/data_frame.dart';
import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/http3/headers_frame.dart';
import 'package:quic_lib/src/http3/http3_connection.dart';
import 'package:quic_lib/src/http3/http3_request.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
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
  group('Http3Connection', () {
    test('sendRequest returns a stream ID', () async {
      final conn = Http3Connection(quicConnection: FakeQuicConnection());
      final request = Http3Request(method: 'GET', path: '/');
      final streamId = await conn.sendRequest(request);
      expect(streamId, equals(0));
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
    });

    test('onStreamFrame with DATA stores data frames', () {
      final conn = Http3Connection(quicConnection: Object());
      final data = Http3DataFrame(data: [0x03, 0x04]);
      final frame = data.toFrame();
      conn.onStreamFrame(4, frame);
      final pending = conn.getPendingData(4);
      expect(pending, hasLength(1));
      expect(pending.first, equals(data));
    });

    test('onStreamFrame with GOAWAY sets isClosing', () {
      final conn = Http3Connection(quicConnection: Object());
      final frame = Http3Frame(type: Http3FrameType.goaway, payload: []);
      conn.onStreamFrame(0, frame);
      expect(conn.isClosing, isTrue);
    });
  });
}

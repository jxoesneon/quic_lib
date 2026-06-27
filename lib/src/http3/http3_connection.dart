import 'dart:async';
import 'dart:typed_data';

import 'data_frame.dart';
import 'frame_types.dart';
import 'headers_frame.dart';
import 'settings_frame.dart';

/// Placeholder for an HTTP/3 request stream.
class Http3Stream {
  final int streamId;
  Http3Stream(this.streamId);
}

typedef HeadersFrame = Http3HeadersFrame;
typedef DataFrame = Http3DataFrame;

/// Manages an HTTP/3 connection over a QUIC transport.
///
/// Per RFC 9114, an HTTP/3 connection operates on a QUIC connection and
/// exchanges frames on QUIC streams. Stream 0 is the control stream.
///
/// **Status:** Scaffold — control stream handling and request/response
/// routing are not yet implemented.
class Http3Connection {
  final Object _quicConnection; // Will be QuicConnection once fully wired.

  final Http3SettingsFrame _localSettings;
  Http3SettingsFrame _peerSettings = Http3SettingsFrame();
  bool _settingsExchanged = false;

  bool _isClosing = false;
  final Map<int, HeadersFrame> _pendingHeaders = {};
  final Map<int, List<DataFrame>> _pendingData = {};

  Http3Connection({
    required Object quicConnection,
    Http3SettingsFrame? localSettings,
  })  : _quicConnection = quicConnection,
        _localSettings = localSettings ?? Http3SettingsFrame.from(
              maxFieldSectionSize: 16384,
              maxTableCapacity: 0,
              blockedStreams: 0,
            );

  /// The underlying QUIC connection.
  Object get quicConnection => _quicConnection;

  /// Local SETTINGS that will be sent to the peer.
  Http3SettingsFrame get localSettings => _localSettings;

  /// SETTINGS received from the peer.
  Http3SettingsFrame get peerSettings => _peerSettings;

  /// True once the peer's SETTINGS frame has been received.
  bool get settingsExchanged => _settingsExchanged;

  /// True once a GOAWAY frame has been received.
  bool get isClosing => _isClosing;

  /// Pending HEADERS frame for a given stream.
  HeadersFrame? getPendingHeaders(int streamId) => _pendingHeaders[streamId];

  /// Pending DATA frames for a given stream.
  List<DataFrame> getPendingData(int streamId) =>
      List.unmodifiable(_pendingData[streamId] ?? []);

  /// Initiate the HTTP/3 connection by sending a SETTINGS frame on the
  /// control stream.
  ///
  /// **Not yet implemented.** The control stream and frame encoder are still
  /// under development.
  void sendSettings() {
    throw UnimplementedError(
      'Http3Connection.sendSettings is not yet implemented. '
      'Control stream creation and SETTINGS frame encoding are pending.',
    );
  }

  /// Process a received SETTINGS frame from the peer's control stream.
  void onSettingsReceived(Http3SettingsFrame settings) {
    _peerSettings = settings;
    _settingsExchanged = true;
  }

  /// Send an HTTP/3 request.
  ///
  /// Allocates a new client-initiated bidirectional stream, creates an
  /// [Http3Stream] for it, and returns the stream ID.
  Future<int> sendRequest(Object request) async {
    final quic = _quicConnection as dynamic;
    final streamId = quic.openBidirectionalStream() as int;
    // TODO: Create Http3Stream and wire into request lifecycle.
    return streamId;
  }

  /// Process received frames on a QUIC stream.
  void onStreamFrame(int streamId, Http3Frame frame) {
    switch (frame.type) {
      case Http3FrameType.headers:
        _pendingHeaders[streamId] = HeadersFrame.fromPayload(frame.payload);
        break;
      case Http3FrameType.data:
        final dataFrame = DataFrame.fromPayload(frame.payload);
        _pendingData.putIfAbsent(streamId, () => []).add(dataFrame);
        break;
      case Http3FrameType.settings:
        onSettingsReceived(
          Http3SettingsFrame.parsePayload(Uint8List.fromList(frame.payload)),
        );
        break;
      case Http3FrameType.goaway:
        _isClosing = true;
        break;
      default:
        // No-op for unhandled frame types.
        break;
    }
  }

  /// Gracefully close the HTTP/3 connection.
  void close() {
    // TODO: Send GOAWAY frame, drain streams, close QUIC connection.
  }
}

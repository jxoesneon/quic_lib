import 'dart:async';

import 'frame_types.dart';
import 'settings_frame.dart';

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

  Http3Connection({
    required Object quicConnection,
    Http3SettingsFrame? localSettings,
  })  : _quicConnection = quicConnection,
        _localSettings = localSettings ??
            Http3SettingsFrame.from(
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
  /// **Not yet implemented.** Requires:
  /// - Request stream allocation
  /// - QPACK header encoding
  /// - HEADERS + DATA frame assembly
  /// - QUIC stream framing
  Future<void> sendRequest(Object request) async {
    throw UnimplementedError(
      'Http3Connection.sendRequest is not yet implemented. '
      'Request stream allocation, QPACK encoding, and HEADERS/DATA frame '
      'assembly are pending.',
    );
  }

  /// Process received frames on a QUIC stream.
  void onStreamFrame(int streamId, Http3Frame frame) {
    throw UnimplementedError(
      'Http3Connection.onStreamFrame is not yet implemented. '
      'Frame dispatch to request/response handlers is pending.',
    );
  }

  /// Gracefully close the HTTP/3 connection.
  void close() {
    // TODO: Send GOAWAY frame, drain streams, close QUIC connection.
  }
}

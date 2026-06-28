import 'dart:async';
import 'dart:typed_data';

import 'capsule_protocol.dart';
import 'http3_connection.dart';

/// Represents an active WebTransport session over HTTP/3.
class WebTransportSession {
  final Http3Connection connection;
  final int sessionId;
  final _incomingStreams = StreamController<Uint8List>.broadcast();
  final _datagrams = StreamController<Uint8List>.broadcast();
  bool _closed = false;

  WebTransportSession(this.connection, this.sessionId);

  Stream<Uint8List> get incomingStreams => _incomingStreams.stream;
  Stream<Uint8List> get datagrams => _datagrams.stream;
  bool get isClosed => _closed;

  /// Send a WebTransport stream (maps to a new QUIC bidirectional stream).
  void sendStream(Uint8List data) {
    if (_closed) throw StateError('Session closed');
    connection.openStream().then((stream) {
      stream.send(data);
    });
  }

  /// Send an unreliable datagram using RFC 9221 DATAGRAM frames.
  void sendDatagram(Uint8List data) {
    if (_closed) throw StateError('Session closed');
    connection.sendDatagram(sessionId, data);
  }

  /// Close the session with an error code.
  void close({int errorCode = 0}) {
    if (_closed) return;
    _closed = true;
    // Send CLOSE_WEBTRANSPORT_SESSION capsule
    final capsule = CloseWebTransportSessionCapsule(errorCode: errorCode);
    connection.sendCapsule(sessionId, capsule);
    _incomingStreams.close();
    _datagrams.close();
  }

  /// Handle incoming capsule from this session.
  void onCapsule(Capsule capsule) {
    if (capsule is DatagramCapsule) {
      _datagrams.add(capsule.data);
    } else if (capsule is CloseWebTransportSessionCapsule) {
      close(errorCode: capsule.errorCode);
    }
  }
}

/// Extended CONNECT request for WebTransport.
/// Method: CONNECT, Protocol: :protocol = webtransport, :scheme, :authority, :path
class WebTransportConnectRequest {
  final String authority;
  final String path;
  final String? origin;

  WebTransportConnectRequest({
    required this.authority,
    required this.path,
    this.origin,
  });
}

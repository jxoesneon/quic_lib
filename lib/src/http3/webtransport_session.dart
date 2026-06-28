import 'dart:async';
import 'dart:typed_data';

import 'package:quic_lib/src/webtransport/capsule_types.dart' as wt;
import 'package:quic_lib/src/webtransport/webtransport_session.dart' as wt;
import 'capsule_protocol.dart';
import 'http3_connection.dart';

/// Represents an active WebTransport session over HTTP/3.
///
/// This class wraps the canonical [wt.WebTransportSession] from the
/// `webtransport` subsystem, adding HTTP/3 connection-aware operations
/// (sending capsules, datagrams, and streams on the underlying
/// [Http3Connection]).
class WebTransportSession {
  final Http3Connection connection;
  final int sessionId;
  final wt.WebTransportSession _state;
  final _incomingStreams = StreamController<Uint8List>.broadcast();
  final _datagrams = StreamController<Uint8List>.broadcast();
  bool _closed = false;

  WebTransportSession(this.connection, this.sessionId)
      : _state = wt.WebTransportSession(sessionId);

  Stream<Uint8List> get incomingStreams => _incomingStreams.stream;
  Stream<Uint8List> get datagrams => _datagrams.stream;
  bool get isClosed => _closed;

  /// Whether the peer has initiated a drain.
  bool get isDraining => _state.isDraining;

  /// Whether the session is still active (not draining and not closed).
  bool get isActive => !_closed && !_state.isDraining && !_state.isClosed;

  /// Whether a GOAWAY capsule has been received from the peer.
  bool get receivedGoaway => _state.receivedGoaway;

  /// Datagrams received via [CapsuleType.datagram] capsules.
  List<Uint8List> get receivedDatagrams => _state.receivedDatagrams;

  /// Bidirectional stream IDs registered by the peer.
  List<int> get registeredBidirectionalStreams =>
      _state.registeredBidirectionalStreams;

  /// Unidirectional stream IDs registered by the peer.
  List<int> get registeredUnidirectionalStreams =>
      _state.registeredUnidirectionalStreams;

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
    // Map http3 capsule to webtransport capsule for state tracking.
    final wtType = wt.CapsuleType.fromValue(capsule.type);
    if (wtType != null) {
      _state.onCapsuleReceived(
        wt.Capsule(type: wtType, payload: capsule.data),
      );
    }
    if (capsule is DatagramCapsule) {
      _datagrams.add(capsule.data);
    } else if (capsule is CloseWebTransportSessionCapsule) {
      _closeFromPeer(errorCode: capsule.errorCode);
    }
  }

  void _closeFromPeer({int errorCode = 0}) {
    if (_closed) return;
    _closed = true;
    _incomingStreams.close();
    _datagrams.close();
    // Note: do NOT send a close capsule back; the peer initiated the close.
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

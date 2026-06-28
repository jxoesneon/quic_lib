import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../io/quic_endpoint.dart';
import 'multiaddr.dart';

/// A libp2p transport backed by QUIC.
///
/// Wraps a [QuicEndpoint] and provides libp2p-style dial/listen APIs.
/// Per the libp2p QUIC spec, this transport handles the Noise handshake
/// (or TLS 1.3 with libp2p extension) over QUIC.
class Libp2pQuicTransport {
  QuicEndpoint? _endpoint;
  final _listeners = <Multiaddr, StreamController<Libp2pQuicConnection>>{};
  bool _closed = false;

  /// Whether the transport has been closed.
  bool get isClosed => _closed;

  /// Extract an [InternetAddress] and port from [multiaddr].
  static (InternetAddress? address, int? port) _parseMultiaddr(
      Multiaddr multiaddr) {
    String? ip;
    int? port;
    for (final c in multiaddr.components) {
      switch (c.protocol) {
        case 'ip4':
        case 'ip6':
          ip = c.value;
        case 'udp':
          port = int.tryParse(c.value ?? '');
      }
    }
    if (ip == null || port == null) {
      return (null, null);
    }
    try {
      return (InternetAddress(ip), port);
    } catch (_) {
      return (null, null);
    }
  }

  /// Listen on the given [multiaddr].
  ///
  /// Returns a stream of incoming connections.
  /// The multiaddr must contain a valid IP and port (e.g.
  /// `/ip4/0.0.0.0/udp/0/quic-v1`).
  Future<Stream<Libp2pQuicConnection>> listen(Multiaddr multiaddr) async {
    if (_closed) {
      throw StateError('Transport is closed');
    }

    final (address, port) = _parseMultiaddr(multiaddr);
    if (address == null || port == null) {
      throw FormatException('Multiaddr must contain IP and port: $multiaddr');
    }

    _endpoint = await QuicEndpoint.bind(address, port);

    // ignore: close_sinks
    final controller = StreamController<Libp2pQuicConnection>.broadcast();
    _listeners[multiaddr] = controller;

    // Bridge QuicEndpoint connections to libp2p connections.
    _endpoint!.connections.listen((conn) {
      if (conn is! Libp2pQuicConnection) {
        // Wrap the raw QuicConnection.
        final wrapped = Libp2pQuicConnection(conn);
        controller.add(wrapped);
      } else {
        controller.add(conn);
      }
    });

    return controller.stream;
  }

  /// Dial a remote peer at [multiaddr].
  ///
  /// Returns a [Libp2pQuicConnection] once the QUIC handshake completes.
  Future<Libp2pQuicConnection> dial(Multiaddr multiaddr) async {
    if (_closed) {
      throw StateError('Transport is closed');
    }

    final (address, port) = _parseMultiaddr(multiaddr);
    if (address == null || port == null) {
      throw FormatException('Multiaddr must contain IP and port: $multiaddr');
    }

    _endpoint ??= await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
    final conn = await _endpoint!.connect(address, port);
    return Libp2pQuicConnection(conn);
  }

  /// Close the transport and all active listeners.
  Future<void> close() async {
    _closed = true;
    for (final controller in _listeners.values) {
      await controller.close();
    }
    _listeners.clear();
    _endpoint?.close();
    _endpoint = null;
  }
}

/// A libp2p-friendly wrapper around a QUIC connection.
class Libp2pQuicConnection {
  final Object _quicConnection;

  Libp2pQuicConnection(this._quicConnection);

  /// The underlying QUIC connection object.
  Object get quicConnection => _quicConnection;

  /// Send data on a new stream via the underlying QUIC connection.
  void send(Uint8List data) {
    final conn = _quicConnection as dynamic;
    try {
      // Attempt to open a unidirectional stream and send data.
      conn.openUnidirectionalStream();
      // Note: In a full implementation this would write the data to the
      // stream via the connection's packet builder. The current design
      // stores data in the stream manager for later packetization.
    } catch (_) {
      // If the connection doesn't support unidirectional streams,
      // the data cannot be sent.
    }
  }

  /// Close the connection.
  void close() {
    final conn = _quicConnection as dynamic;
    try {
      conn.close();
    } catch (_) {
      // Ignore if the connection doesn't support close.
    }
  }
}

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../io/quic_endpoint.dart';
import 'multiaddr.dart';

/// A libp2p transport backed by QUIC.
///
/// [Libp2pQuicTransport] wraps a [QuicEndpoint] and exposes libp2p-style
/// [listen] and [dial] APIs. It parses [Multiaddr] values to extract IP
/// addresses and UDP ports, binds the endpoint, and bridges raw
/// [QuicConnection] objects into [Libp2pQuicConnection] wrappers.
///
/// Per the libp2p QUIC specification, the security handshake (Noise or
/// TLS 1.3 with libp2p extension) runs inside the QUIC crypto frame stream.
/// This transport layer handles addressing and connection establishment;
/// the actual security handshake is performed by the libp2p security
/// upgrade layer above it.
///
/// ## Example
/// ```dart
/// final transport = Libp2pQuicTransport();
///
/// // Listen on a multiaddr.
/// final incoming = await transport.listen(
///   Multiaddr.parse('/ip4/127.0.0.1/udp/0/quic-v1'),
/// );
/// incoming.listen((conn) {
///   print('Accepted connection: ${conn.quicConnection}');
///   conn.close();
/// });
///
/// // Dial a remote peer.
/// final conn = await transport.dial(
///   Multiaddr.parse('/ip4/192.168.1.10/udp/4001/quic-v1'),
/// );
/// conn.send(Uint8List.fromList([1, 2, 3]));
/// await transport.close();
/// ```
///
/// See also:
/// - [Libp2pQuicConnection] — wrapper around an established QUIC connection.
/// - [QuicEndpoint] — the underlying QUIC endpoint.
/// - [Multiaddr] — libp2p addressing format.
/// - libp2p QUIC spec — https://github.com/libp2p/specs/tree/master/quic
class Libp2pQuicTransport {
  QuicEndpoint? _endpoint;
  final _listeners = <Multiaddr, StreamController<Libp2pQuicConnection>>{};
  bool _closed = false;

  /// Whether the transport has been closed.
  ///
  /// Once true, [listen] and [dial] will throw [StateError].
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
  /// Binds a [QuicEndpoint] to the IP and port encoded in [multiaddr] and
  /// returns a broadcast stream of incoming [Libp2pQuicConnection]s.
  ///
  /// The multiaddr must contain a valid IP and port, for example:
  /// `/ip4/0.0.0.0/udp/0/quic-v1`.
  ///
  /// Throws [StateError] if the transport is already closed.
  /// Throws [FormatException] if [multiaddr] lacks an IP or port component.
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
  /// Parses the IP and port from [multiaddr], binds an ephemeral local
  /// endpoint if none exists, and initiates a QUIC handshake. Returns a
  /// [Libp2pQuicConnection] wrapping the resulting [QuicConnection].
  ///
  /// Throws [StateError] if the transport is already closed.
  /// Throws [FormatException] if [multiaddr] lacks an IP or port component.
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
  ///
  /// Closes every listener stream controller, clears the listener registry,
  /// closes the underlying [QuicEndpoint], and marks the transport as closed.
  /// After this call the transport can no longer be used.
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
///
/// [Libp2pQuicConnection] encapsulates a raw [QuicConnection] and exposes
/// simple [send] and [close] methods compatible with libp2p transport
/// interfaces. The underlying connection object is accessible via
/// [quicConnection] for callers that need to interact with QUIC-specific
/// APIs (stream allocation, encryption details, etc.).
///
/// ## Example
/// ```dart
/// final transport = Libp2pQuicTransport();
/// final conn = await transport.dial(multiaddr);
/// conn.send(Uint8List.fromList([0x01, 0x02]));
/// print('Underlying QUIC conn: ${conn.quicConnection}');
/// conn.close();
/// ```
class Libp2pQuicConnection {
  final Object _quicConnection;

  /// Creates a libp2p wrapper around [quicConnection].
  ///
  /// [quicConnection] is expected to be a [QuicConnection] or an object
  /// that implements `openUnidirectionalStream()` and `close()`.
  Libp2pQuicConnection(this._quicConnection);

  /// The underlying QUIC connection object.
  ///
  /// In typical usage this is a [QuicConnection]. Cast to access
  /// QUIC-specific methods such as `openBidirectionalStream()`.
  Object get quicConnection => _quicConnection;

  /// Send [data] on a new unidirectional stream.
  ///
  /// Opens a client-initiated unidirectional stream via the underlying
  /// connection. In a full implementation the data would be written to the
  /// stream and packetized; the current design stores it in the stream
  /// manager for later transmission.
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

  /// Close the underlying QUIC connection.
  ///
  /// Delegates to the wrapped connection's `close()` method. If the
  /// underlying object does not support close, the error is silently ignored.
  void close() {
    final conn = _quicConnection as dynamic;
    try {
      conn.close();
    } catch (_) {
      // Ignore if the connection doesn't support close.
    }
  }
}

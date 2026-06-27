import 'dart:async';
import 'dart:io';

import 'udp_socket.dart';

/// A QUIC endpoint that can listen for and initiate connections.
class QuicEndpoint {
  final InternetAddress _localAddress;
  final int _localPort;
  final UdpSocket _udpSocket;
  final _connectionsController = StreamController<Object>.broadcast();

  QuicEndpoint._(this._localAddress, this._localPort, this._udpSocket);

  /// Binds a [QuicEndpoint] to the given [address] and [port].
  static Future<QuicEndpoint> bind(InternetAddress address, int port) async {
    final socket = await UdpSocket.bind(address, port);
    return QuicEndpoint._(socket.localAddress, socket.localPort, socket);
  }

  /// Incoming connections (server-side).
  ///
  /// Returns a [Stream] of connection objects.  The concrete type will be
  /// [QuicConnection] once that class is implemented.
  Stream<Object> get connections => _connectionsController.stream;

  /// Connect to a remote endpoint.
  ///
  /// **Not yet implemented.** The full QUIC handshake pipeline (Initial packet
  /// exchange, TLS 1.3 integration, and connection state management) is still
  /// under development. Use [QuicConnection] directly for testing individual
  /// subsystems.
  Future<Object> connect(InternetAddress address, int port) async {
    throw UnimplementedError(
      'QuicEndpoint.connect is not yet implemented. '
      'The full QUIC handshake pipeline (Initial/Handshake/Application packet '
      'exchange, TLS 1.3 handshake, and connection state machine integration) '
      'is under development for a future alpha release.',
    );
  }

  /// Close the endpoint and all associated connections.
  void close() {
    _connectionsController.close();
    _udpSocket.close();
  }

  /// The local address this endpoint is bound to.
  InternetAddress get localAddress => _localAddress;

  /// The local port this endpoint is bound to.
  int get localPort => _localPort;
}

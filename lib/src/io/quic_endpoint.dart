import 'dart:async';
import 'dart:io';

import 'udp_socket.dart';
import '../connection/quic_connection.dart';
import '../connection/connection_state_machine.dart';
import '../connection/connection_id_manager.dart';
import '../recovery/packet_number_space.dart';
import '../recovery/rtt_estimator.dart';
import '../recovery/loss_detector.dart';
import '../recovery/pto_scheduler.dart';
import '../recovery/congestion_controller.dart';
import '../streams/stream_id.dart';

/// A QUIC endpoint that can listen for and initiate connections.
class QuicEndpoint {
  final InternetAddress _localAddress;
  final int _localPort;
  final UdpSocket _udpSocket;
  final _connectionsController = StreamController<Object>.broadcast();
  final List<QuicConnection> _connections = [];
  final Map<QuicConnection, InternetAddress> _remoteAddresses = {};
  final Map<QuicConnection, int> _remotePorts = {};

  QuicEndpoint._(this._localAddress, this._localPort, this._udpSocket);

  /// Binds a [QuicEndpoint] to the given [address] and [port].
  static Future<QuicEndpoint> bind(InternetAddress address, int port) async {
    final socket = await UdpSocket.bind(address, port);
    return QuicEndpoint._(socket.localAddress, socket.localPort, socket);
  }

  /// Incoming connections (server-side).
  ///
  /// Returns a [Stream] of connection objects. The concrete type is
  /// [QuicConnection].
  Stream<Object> get connections => _connectionsController.stream;

  /// All active connections.
  List<QuicConnection> get activeConnections => List.unmodifiable(_connections);

  /// Connect to a remote endpoint.
  ///
  /// Creates a [QuicConnection] with all required subsystems, transitions it
  /// to handshaking, and begins the QUIC handshake.
  ///
  /// **Note:** The full handshake (Initial packet exchange, TLS 1.3, key
  /// derivation) is not yet wired end-to-end. This method scaffolds the
  /// connection creation but the caller must drive the handshake manually.
  Future<QuicConnection> connect(InternetAddress address, int port) async {
    // Create all subsystems required for a QUIC connection.
    final stateMachine = ConnectionStateMachine();
    final cidManager = ConnectionIdManager();
    final pnSpaceManager = PacketNumberSpaceManager();
    final rttEstimator = RttEstimator();
    final lossDetector = LossDetector();
    final ptoScheduler = PtoScheduler(rttEstimator);
    final congestionController = CongestionController();
    final streamIdAllocator = StreamIdAllocator();

    final connection = QuicConnection(
      stateMachine: stateMachine,
      cidManager: cidManager,
      pnSpaceManager: pnSpaceManager,
      rttEstimator: rttEstimator,
      lossDetector: lossDetector,
      ptoScheduler: ptoScheduler,
      congestionController: congestionController,
      streamIdAllocator: streamIdAllocator,
    );

    // Transition to handshaking to begin the QUIC handshake.
    stateMachine.transitionTo(ConnectionState.handshaking, reason: 'Connect to $address:$port');

    _connections.add(connection);
    _remoteAddresses[connection] = address;
    _remotePorts[connection] = port;
    return connection;
  }

  /// Returns the remote address for a given connection, or null if unknown.
  InternetAddress? getRemoteAddress(QuicConnection conn) => _remoteAddresses[conn];

  /// Returns the remote port for a given connection, or null if unknown.
  int? getRemotePort(QuicConnection conn) => _remotePorts[conn];

  /// Migrate a connection to a new remote address and port.
  Future<void> migrateConnection(QuicConnection conn, InternetAddress newAddress, int newPort) async {
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Close the endpoint and all associated connections.
  void close() {
    for (final conn in _connections) {
      conn.abort();
    }
    _connections.clear();
    _connectionsController.close();
    _udpSocket.close();
  }

  /// The local address this endpoint is bound to.
  InternetAddress get localAddress => _localAddress;

  /// The local port this endpoint is bound to.
  int get localPort => _localPort;
}

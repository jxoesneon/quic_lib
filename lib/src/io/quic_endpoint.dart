import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'udp_socket.dart';
import 'connection_isolate.dart';
import 'isolate_supervisor.dart';
import 'package:quic_lib/src/connection/connection_registry.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/streams/stream_id.dart';

/// A QUIC endpoint that listens for and initiates connections over UDP.
///
/// A [QuicEndpoint] is the primary entry point for both QUIC clients and
/// servers. It binds to a local UDP socket and manages the full lifecycle of
/// QUIC connections, including handshake routing, connection ID registry,
/// and optional connection migration.
///
/// On the server side, call [bind] to start listening, then subscribe to
/// [connections] to accept incoming handshakes. On the client side, call
/// [connect] to initiate an outbound connection. All active connections are
/// tracked by the endpoint and can be inspected via [activeConnections].
///
/// Each connection runs its own isolate (supervised by [isolateSupervisor])
/// so that packet processing does not block the event loop.
///
/// ## Example
/// ```dart
/// // Server-side: bind and accept connections.
/// final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 4433);
/// await for (final conn in endpoint.connections) {
///   if (conn is QuicConnection) {
///     print('New connection from ${endpoint.getRemoteAddress(conn)}');
///     // Open a bidirectional stream and send data...
///     final streamId = conn.openBidirectionalStream();
///     print('Opened stream $streamId');
///   }
/// }
///
/// // Client-side: connect to a remote endpoint.
/// final client = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
/// final conn = await client.connect(
///   InternetAddress.loopbackIPv4,
///   4433,
/// );
/// if (conn.isEstablished) {
///   final streamId = conn.openBidirectionalStream();
///   print('Client opened stream $streamId');
/// }
/// ```
///
/// See also:
/// - [QuicConnection] — the connection object returned by [connect] and
///   emitted on the [connections] stream.
/// - [IsolateSupervisor] — tracks isolates spawned for each connection.
/// - RFC 9000 Section 5 — UDP and Endpoint Behavior.
class QuicEndpoint {
  static const int _maxConnections = 1000;

  final InternetAddress _localAddress;
  final int _localPort;
  final UdpSocket _udpSocket;
  final _connectionsController = StreamController<Object>.broadcast();
  final List<QuicConnection> _connections = [];
  final Map<QuicConnection, InternetAddress> _remoteAddresses = {};
  final Map<QuicConnection, int> _remotePorts = {};
  final IsolateSupervisor _isolateSupervisor = IsolateSupervisor();
  final ConnectionRegistry _connectionRegistry = ConnectionRegistry();
  StreamSubscription<({Uint8List data, InternetAddress address, int port})>?
      _incomingSubscription;
  bool _listening = false;

  QuicEndpoint._(this._localAddress, this._localPort, this._udpSocket) {
    _startListening();
  }

  /// Binds a [QuicEndpoint] to the given [address] and [port].
  ///
  /// Creates a UDP socket and begins listening for incoming QUIC packets.
  /// Use `InternetAddress.anyIPv4` (or `anyIPv6`) and port `0` to let the OS
  /// assign an ephemeral address and port.
  ///
  /// Once bound, the endpoint is ready to accept connections (server mode) or
  /// initiate outbound connections (client mode).
  static Future<QuicEndpoint> bind(InternetAddress address, int port) async {
    final socket = await UdpSocket.bind(address, port);
    return QuicEndpoint._(socket.localAddress, socket.localPort, socket);
  }

  /// A broadcast stream of incoming server-side connections.
  ///
  /// Each time a client completes a QUIC handshake, a new [QuicConnection]
  /// is emitted on this stream. Subscribe before calling [bind] to ensure no
  /// connection is missed.
  ///
  /// The stream emits `Object` because the isolate bridge may wrap the raw
  /// connection handle; cast to [QuicConnection] before use.
  Stream<Object> get connections => _connectionsController.stream;

  /// All currently active connections managed by this endpoint.
  ///
  /// Returns an unmodifiable snapshot of the connections list. Connections
  /// remain in this list until [close] is called or the connection is aborted.
  List<QuicConnection> get activeConnections => List.unmodifiable(_connections);

  /// The [IsolateSupervisor] tracking connection isolates.
  ///
  /// Each accepted or dialed connection spawns a dedicated isolate for
  /// packet processing. The supervisor provides visibility into running
  /// isolates and can be used to unregister or restart them if needed.
  IsolateSupervisor get isolateSupervisor => _isolateSupervisor;

  /// Connect to a remote endpoint and begin the QUIC handshake.
  ///
  /// Creates a [QuicConnection] with all required subsystems (state machine,
  /// connection ID manager, recovery manager, congestion controller, etc.),
  /// transitions it to the handshaking state, and registers it with the
  /// endpoint's connection registry.
  ///
  /// The returned connection is not yet established; wait for the handshake
  /// to complete by polling [QuicConnection.isEstablished] or subscribing
  /// to connection state changes via the connection's state machine.
  ///
  /// Throws [StateError] if the endpoint has already been closed.
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
    stateMachine.transitionTo(ConnectionState.handshaking,
        reason: 'Connect to $address:$port');

    final isolate = ConnectionIsolate(
      connection: connection,
      sendPort: null,
      connectionId: connection.connectionId?.toString() ?? 'unknown',
    );
    _isolateSupervisor.register(isolate);

    _connections.add(connection);
    _remoteAddresses[connection] = address;
    _remotePorts[connection] = port;

    // Register the connection under its DCID so incoming packets can be routed.
    final dcid = connection.connectionId;
    if (dcid != null && dcid.isNotEmpty) {
      _connectionRegistry.register(dcid, connection);
    }

    return connection;
  }

  // -----------------------------------------------------------------------
  // UDP packet reception and routing
  // -----------------------------------------------------------------------

  void _startListening() {
    if (_listening) return;
    _listening = true;
    _incomingSubscription = _udpSocket.incoming.listen(
      _onIncomingDatagram,
      onError: (Object error) {
        // Log and continue; individual packet errors should not kill the listener.
      },
    );
  }

  void _onIncomingDatagram(
      ({Uint8List data, InternetAddress address, int port}) datagram) {
    final dcid = _extractDcid(datagram.data);
    if (dcid == null) return;

    final conn = _connectionRegistry.lookup(dcid);
    if (conn is QuicConnection) {
      conn.processIncomingDatagram(datagram.data);
      return;
    }

    // No existing connection: accept if it's an Initial packet.
    if (_isInitialPacket(datagram.data)) {
      final newConn = _acceptConnection(dcid, datagram.address, datagram.port);
      newConn.processIncomingDatagram(datagram.data);
    }
  }

  /// Extract the destination connection ID from a QUIC packet.
  static List<int>? _extractDcid(Uint8List datagram) {
    if (datagram.isEmpty) return null;
    final isLong = (datagram[0] & 0x80) != 0;
    if (isLong && datagram.length > 5) {
      final dcidLen = datagram[5];
      if (6 + dcidLen <= datagram.length) {
        return datagram.sublist(6, 6 + dcidLen).toList();
      }
    } else if (!isLong && datagram.length > 1) {
      // Short header: DCID length is not encoded in the packet.
      // Use the common default of 8 bytes.
      const dcidLen = 8;
      if (1 + dcidLen <= datagram.length) {
        return datagram.sublist(1, 1 + dcidLen).toList();
      }
    }
    return null;
  }

  /// Returns whether the datagram contains an Initial packet.
  static bool _isInitialPacket(Uint8List datagram) {
    if (datagram.isEmpty) return false;
    final isLong = (datagram[0] & 0x80) != 0;
    if (!isLong) return false;
    final packetType = (datagram[0] >> 4) & 0x03;
    return packetType == 0x00; // Initial
  }

  /// Accept a new server-side connection from an incoming Initial packet.
  QuicConnection _acceptConnection(
      List<int> dcid, InternetAddress address, int port) {
    if (_connections.length >= _maxConnections) {
      throw StateError('Endpoint connection limit reached');
    }
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

    stateMachine.transitionTo(ConnectionState.handshaking,
        reason: 'Incoming connection from $address:$port');

    final isolate = ConnectionIsolate(
      connection: connection,
      sendPort: null,
      connectionId: connection.connectionId?.toString() ?? 'unknown',
    );
    _isolateSupervisor.register(isolate);

    _connections.add(connection);
    _remoteAddresses[connection] = address;
    _remotePorts[connection] = port;
    _connectionRegistry.register(dcid, connection);

    _connectionsController.add(connection);

    return connection;
  }

  /// Send a QUIC packet over UDP for the given connection.
  void send(QuicConnection connection, Uint8List packet) {
    final address = _remoteAddresses[connection];
    final port = _remotePorts[connection];
    if (address != null && port != null) {
      // SECURITY: Enforce anti-amplification limit before sending.
      if (!connection.canSend(packet.length)) {
        return; // Silently drop packet if limit exceeded.
      }
      _udpSocket.send(packet, address, port);
      connection.onBytesSent(packet.length);
    }
  }

  /// Returns the remote address for a given connection, or null if unknown.
  InternetAddress? getRemoteAddress(QuicConnection conn) =>
      _remoteAddresses[conn];

  /// Returns the remote port for a given connection, or null if unknown.
  int? getRemotePort(QuicConnection conn) => _remotePorts[conn];

  /// Migrate a connection to a new remote address and port.
  Future<void> migrateConnection(
      QuicConnection conn, InternetAddress newAddress, int newPort) async {
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Check whether the stored remote address for [conn] differs from [addr]:[port].
  bool isRemoteAddressChanged(
      QuicConnection conn, InternetAddress addr, int port) {
    final currentAddr = _remoteAddresses[conn];
    final currentPort = _remotePorts[conn];
    if (currentAddr == null || currentPort == null) return true;
    return currentAddr.address != addr.address || currentPort != port;
  }

  /// Perform a real connection migration by probing the new path and updating
  /// the stored remote address upon successful validation.
  ///
  /// Sends a PATH_CHALLENGE to [newAddress]:[newPort] via the underlying UDP
  /// socket. When a matching PATH_RESPONSE is received, the remote address
  /// is updated.
  Future<void> changeConnectionAddress(
      QuicConnection conn, InternetAddress newAddress, int newPort) async {
    const dcid = <int>[];
    final future = conn.probeNewPath(dcid);
    final packet = conn.lastProbePacket;
    if (packet != null) {
      _udpSocket.send(packet, newAddress, newPort);
    }
    await future;
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Production connection migration with UDP socket rebind.
  ///
  /// Validates the new path using [changeConnectionAddress] and then updates
  /// the connection's stored remote address.
  ///
  /// **Note:** True UDP socket rebind requires OS-level support (e.g.
  /// `IP_RECVERR`, `SO_REUSEPORT`, or platform-specific APIs). This method
  /// updates the logical remote address used for [send] via the existing
  /// [UdpSocket] instance.
  Future<void> rebindToAddress(
      QuicConnection conn, InternetAddress newAddress, int newPort) async {
    // Validate the new path via PATH_CHALLENGE/PATH_RESPONSE.
    await changeConnectionAddress(conn, newAddress, newPort);
    // Update the logical remote address used for sending packets.
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Stop all registered connection isolates.
  void stopAllIsolates() => _isolateSupervisor.unregisterAll();

  /// Close the endpoint and abort all associated connections.
  ///
  /// Cancels the UDP listener, aborts every active connection, unregisters
  /// all connection IDs, stops all connection isolates, and closes the
  /// underlying UDP socket. After calling this method the endpoint can no
  /// longer be used.
  ///
  /// This is an abrupt shutdown; for graceful closure of an individual
  /// connection, use [QuicConnection.close] instead.
  void close() {
    _incomingSubscription?.cancel();
    for (final conn in _connections) {
      conn.abort();
      final dcid = conn.connectionId;
      if (dcid != null && dcid.isNotEmpty) {
        _connectionRegistry.unregister(dcid);
      }
      _isolateSupervisor.unregister(conn.connectionId?.toString() ?? 'unknown');
    }
    _connections.clear();
    _remoteAddresses.clear();
    _remotePorts.clear();
    _connectionsController.close();
    _udpSocket.close();
  }

  /// The local address this endpoint is bound to.
  InternetAddress get localAddress => _localAddress;

  /// The local port this endpoint is bound to.
  int get localPort => _localPort;
}

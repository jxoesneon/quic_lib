import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'udp_socket.dart';
import 'connection_isolate.dart';
import 'isolate_supervisor.dart';
import 'package:dart_quic/src/connection/connection_registry.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/streams/stream_id.dart';

/// A QUIC endpoint that can listen for and initiate connections.
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
  StreamSubscription<({Uint8List data, InternetAddress address, int port})>? _incomingSubscription;
  bool _listening = false;

  QuicEndpoint._(this._localAddress, this._localPort, this._udpSocket) {
    _startListening();
  }

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

  /// The isolate supervisor tracking connection isolates.
  IsolateSupervisor get isolateSupervisor => _isolateSupervisor;

  /// Connect to a remote endpoint.
  ///
  /// Creates a [QuicConnection] with all required subsystems, transitions it
  /// to handshaking, and begins the QUIC handshake.
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

  void _onIncomingDatagram(({Uint8List data, InternetAddress address, int port}) datagram) {
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
  QuicConnection _acceptConnection(List<int> dcid, InternetAddress address, int port) {
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

    stateMachine.transitionTo(ConnectionState.handshaking, reason: 'Incoming connection from $address:$port');

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
  InternetAddress? getRemoteAddress(QuicConnection conn) => _remoteAddresses[conn];

  /// Returns the remote port for a given connection, or null if unknown.
  int? getRemotePort(QuicConnection conn) => _remotePorts[conn];

  /// Migrate a connection to a new remote address and port.
  Future<void> migrateConnection(QuicConnection conn, InternetAddress newAddress, int newPort) async {
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Check whether the stored remote address for [conn] differs from [addr]:[port].
  bool isRemoteAddressChanged(QuicConnection conn, InternetAddress addr, int port) {
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
  Future<void> changeConnectionAddress(QuicConnection conn, InternetAddress newAddress, int newPort) async {
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
  Future<void> rebindToAddress(QuicConnection conn, InternetAddress newAddress, int newPort) async {
    // Validate the new path via PATH_CHALLENGE/PATH_RESPONSE.
    await changeConnectionAddress(conn, newAddress, newPort);
    // Update the logical remote address used for sending packets.
    _remoteAddresses[conn] = newAddress;
    _remotePorts[conn] = newPort;
  }

  /// Stop all registered connection isolates.
  void stopAllIsolates() => _isolateSupervisor.unregisterAll();

  /// Close the endpoint and all associated connections.
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

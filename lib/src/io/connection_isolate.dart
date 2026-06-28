import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import '../connection/quic_connection.dart';

/// Manages a single QUIC connection inside its own isolate.
///
/// The isolate owns the [connection] and communicates with the supervisor
/// via [sendPort]. Incoming packets are delivered as messages; outgoing
/// packets are sent back through the port.
///
/// Message-passing pattern:
/// - Supervisor -> Isolate: `{ 'type': 'packet', 'data': Uint8List, ... }`
/// - Isolate -> Supervisor: `{ 'type': 'packet', 'data': Uint8List, ... }`
/// - Isolate -> Supervisor: `{ 'type': 'close', 'connectionId': String }`
class ConnectionIsolate {
  final QuicConnection connection;

  /// Port back to the supervisor isolate.
  final SendPort? sendPort;
  final String connectionId;
  final ReceivePort _receivePort = ReceivePort();
  StreamSubscription<dynamic>? _subscription;
  bool _running = false;

  ConnectionIsolate({
    required this.connection,
    required this.sendPort,
    required this.connectionId,
  });

  /// Start the isolate loop.
  ///
  /// Begins listening for incoming packets from the supervisor and
  /// notifies the supervisor of readiness via [sendPort].
  void start() {
    if (_running) return;
    _running = true;
    _subscription = _receivePort.listen(_onMessage);
    sendPort?.send({
      'type': 'ready',
      'port': _receivePort.sendPort,
      'connectionId': connectionId,
    });
  }

  /// Stop the isolate loop.
  void stop() {
    _running = false;
    _subscription?.cancel();
    sendPort?.send({
      'type': 'close',
      'connectionId': connectionId,
    });
  }

  void _onMessage(dynamic message) {
    if (!_running || message is! Map<String, dynamic>) return;
    switch (message['type']) {
      case 'packet':
        final data = message['data'] as Uint8List?;
        if (data != null) {
          connection.processIncomingDatagram(data);
        }
      case 'stop':
        stop();
    }
  }

  /// Send an outgoing packet to the supervisor for UDP transmission.
  void sendPacket(Uint8List data, String address, int port) {
    sendPort?.send({
      'type': 'packet',
      'data': data,
      'address': address,
      'port': port,
      'connectionId': connectionId,
    });
  }

  /// Whether the isolate loop is currently running.
  bool get isRunning => _running;

  /// The [SendPort] that the supervisor should use to send messages to this isolate.
  SendPort get incomingPort => _receivePort.sendPort;
}

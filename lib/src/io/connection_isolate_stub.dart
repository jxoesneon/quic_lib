import 'dart:async';
import 'dart:typed_data';

import '../connection/quic_connection.dart';

/// Manages a single QUIC connection inside its own isolate.
///
/// Stub implementation for platforms without isolate support.
/// Runs all connection processing synchronously in the main thread.
class ConnectionIsolate {
  final QuicConnection connection;

  /// Port back to the supervisor (ignored in stub).
  final dynamic sendPort;
  final String connectionId;
  final StreamController<dynamic> _controller = StreamController<dynamic>();
  StreamSubscription<dynamic>? _subscription;
  bool _running = false;

  ConnectionIsolate({
    required this.connection,
    required this.sendPort,
    required this.connectionId,
  });

  /// Start the isolate loop.
  void start() {
    if (_running) return;
    _running = true;
    _subscription = _controller.stream.listen(_onMessage);
  }

  /// Stop the isolate loop.
  void stop() {
    _running = false;
    _subscription?.cancel();
    _controller.close();
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
    // No-op in stub.
  }

  /// Whether the isolate loop is currently running.
  bool get isRunning => _running;

  /// The port that the supervisor should use to send messages to this isolate.
  dynamic get incomingPort => _controller;
}

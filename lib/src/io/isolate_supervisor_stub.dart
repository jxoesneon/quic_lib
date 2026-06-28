import 'dart:typed_data';

import 'connection_isolate.dart';

/// Tracks active connection isolates by connection ID.
///
/// Stub implementation for platforms without isolate support.
class IsolateSupervisor {
  final Map<String, ConnectionIsolate> _isolates = {};
  final Map<String, dynamic> _isolatePorts = {};

  /// Register an active connection isolate.
  void register(ConnectionIsolate isolate) {
    _isolates[isolate.connectionId] = isolate;
  }

  /// Unregister a connection by its ID.
  void unregister(String connectionId) {
    _isolates.remove(connectionId);
    _isolatePorts.remove(connectionId);
  }

  /// Number of active isolates.
  int get count => _isolates.length;

  /// Whether a connection ID is currently registered.
  bool contains(String connectionId) => _isolates.containsKey(connectionId);

  /// Retrieve a registered isolate by ID.
  ConnectionIsolate? get(String connectionId) => _isolates[connectionId];

  /// Unregister all isolates.
  void unregisterAll() {
    _isolates.clear();
    _isolatePorts.clear();
  }

  // -----------------------------------------------------------------------
  // Message routing
  // -----------------------------------------------------------------------

  /// Handle a message received from an isolate (e.g., 'ready' or 'close').
  void onIsolateMessage(dynamic message) {
    if (message is! Map<String, dynamic>) return;
    final type = message['type'] as String?;
    final connectionId = message['connectionId'] as String?;
    if (connectionId == null) return;
    switch (type) {
      case 'ready':
        final port = message['port'] as dynamic;
        if (port != null) {
          _isolatePorts[connectionId] = port;
        }
      case 'close':
        _isolates.remove(connectionId);
        _isolatePorts.remove(connectionId);
    }
  }

  /// Send a packet to the isolate identified by [connectionId].
  void sendPacket(String connectionId, Uint8List data) {
    final isolate = _isolates[connectionId];
    if (isolate != null) {
      isolate.connection.processIncomingDatagram(data);
    }
  }

  /// Request an isolate to stop.
  void stopIsolate(String connectionId) {
    final isolate = _isolates[connectionId];
    isolate?.stop();
  }
}

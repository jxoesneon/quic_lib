import 'capsule_types.dart';
import 'webtransport_session.dart';

/// Manages multiple WebTransport sessions over a single QUIC connection.
///
/// Each session is identified by its bidirectional stream ID. The manager
/// creates sessions, routes incoming capsules, and tracks session lifecycle.
class WebTransportSessionManager {
  final Map<int, WebTransportSession> _sessions = {};

  /// All currently active sessions.
  List<WebTransportSession> get sessions => List.unmodifiable(_sessions.values);

  /// Number of active sessions.
  int get sessionCount => _sessions.length;

  /// Create a new session for the given [streamId].
  ///
  /// Throws [StateError] if a session already exists for [streamId].
  WebTransportSession createSession(int streamId) {
    if (_sessions.containsKey(streamId)) {
      throw StateError('Session already exists for stream $streamId');
    }
    final session = WebTransportSession(streamId);
    _sessions[streamId] = session;
    return session;
  }

  /// Retrieve an existing session by [streamId], or null if none exists.
  WebTransportSession? getSession(int streamId) => _sessions[streamId];

  /// Route a [capsule] to the session identified by [streamId].
  ///
  /// If no session exists for [streamId], a new one is created automatically.
  void routeCapsule(int streamId, Capsule capsule) {
    final session =
        _sessions.putIfAbsent(streamId, () => WebTransportSession(streamId));
    session.onCapsuleReceived(capsule);
  }

  /// Remove a closed or drained session.
  void removeSession(int streamId) {
    _sessions.remove(streamId);
  }

  /// Remove all sessions that are closed or draining.
  int cleanupInactiveSessions() {
    var removed = 0;
    _sessions.removeWhere((streamId, session) {
      if (session.isClosed || session.isDraining) {
        removed++;
        return true;
      }
      return false;
    });
    return removed;
  }

  /// Close all sessions gracefully and clear the registry.
  void closeAll() {
    for (final session in _sessions.values) {
      if (session.isActive) {
        session.initiateClose();
      }
    }
    _sessions.clear();
  }
}

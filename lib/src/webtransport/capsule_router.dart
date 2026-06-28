import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';

/// Routes WebTransport capsules to their associated [WebTransportSession].
///
/// Each session is keyed by its QUIC stream ID. If a capsule arrives on a
/// stream for which no session exists, a new [WebTransportSession] is
/// created automatically.
class CapsuleRouter {
  final Map<int, WebTransportSession> _sessions = {};

  /// Route a [capsule] received on the given [streamId].
  ///
  /// If no session exists for [streamId], one is created before forwarding
  /// the capsule.
  void routeCapsule(int streamId, Capsule capsule) {
    final session = _sessions.putIfAbsent(
      streamId,
      () => WebTransportSession(streamId),
    );
    session.onCapsuleReceived(capsule);
  }

  /// Retrieve an existing session by its stream ID.
  WebTransportSession? getSession(int streamId) => _sessions[streamId];

  /// Remove and close the session associated with [streamId].
  void closeSession(int streamId) {
    _sessions.remove(streamId);
  }
}

/// States for the DCUtR (Direct Connection Upgrade through Relay) handshake.
enum DCUtRState {
  /// No handshake in progress.
  idle,

  /// CONNECT message has been sent (dialer).
  connectSent,

  /// SYNC message has been received (dialer).
  syncReceived,

  /// Hole-punching handshake is complete.
  connected,

  /// Handshake failed or timed out.
  failed,
}

/// Finite state machine that tracks DCUtR handshake progress.
class DCUtRStateMachine {
  DCUtRState _state = DCUtRState.idle;

  /// Current state of the DCUtR handshake.
  DCUtRState get state => _state;

  /// Whether the handshake has reached the connected state.
  bool get isConnected => _state == DCUtRState.connected;

  /// Transition from [DCUtRState.idle] to [DCUtRState.connectSent] when the dialer sends a
  /// CONNECT message.
  void onConnectSent() {
    if (_state == DCUtRState.idle) {
      _state = DCUtRState.connectSent;
    }
  }

  /// Transition toward [DCUtRState.connected] when a SYNC is received.
  ///
  /// - [DCUtRState.connectSent] → [DCUtRState.syncReceived]
  /// - [DCUtRState.syncReceived] → [DCUtRState.connected]
  void onSyncReceived() {
    if (_state == DCUtRState.connectSent) {
      _state = DCUtRState.syncReceived;
    } else if (_state == DCUtRState.syncReceived) {
      _state = DCUtRState.connected;
    }
  }

  /// Transition from [DCUtRState.idle] directly to [DCUtRState.connected] when the listener
  /// receives a CONNECT message.
  void onConnectReceived() {
    if (_state == DCUtRState.idle) {
      _state = DCUtRState.connected;
    }
  }

  /// Transition to [DCUtRState.failed] from any state on timeout.
  void onTimeout() {
    _state = DCUtRState.failed;
  }
}

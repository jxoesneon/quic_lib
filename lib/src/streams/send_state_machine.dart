/// Lifecycle states for the sending half of a QUIC stream (RFC 9000 Section 3.1).
///
/// These states track how much of the stream's data has been sent and
/// acknowledged, from the initial [ready] state through terminal states
/// [received] (success) or [resetReceived] (aborted). The [SendStateMachine]
/// enforces valid transitions and prevents illegal state changes.
///
/// See also:
/// - [SendStateMachine] — manages transitions between these states.
/// - [QuicStream] — the stream that owns this send state machine.
/// - RFC 9000 Section 3.1 — stream states.
enum SendStreamState {
  /// Stream is ready to send data.
  ready,

  /// Data has been sent; waiting for ACK.
  send,

  /// All data including FIN has been sent.
  sent,

  /// All data has been acknowledged by the peer (terminal success).
  received,

  /// RESET_STREAM was sent by this endpoint.
  resetSent,

  /// RESET_STREAM was acknowledged by the peer (terminal aborted).
  resetReceived,
}

/// Manages the lifecycle of the sending half of a QUIC stream (RFC 9000 Section 3.1).
///
/// [SendStateMachine] tracks whether a stream is ready to send, has unacknowledged
/// data, or has reached a terminal state. It is owned by a [QuicStream] and is
/// driven by packet-level events such as transmission, acknowledgment, and reset.
///
/// ## Example
/// ```dart
/// final sm = SendStateMachine();
/// sm.onDataSent();
/// sm.onFinSent();
/// sm.onAllDataAcked();
/// assert(sm.isTerminal);
/// ```
///
/// See also:
/// - [SendStreamState] — the individual states this machine tracks.
/// - [QuicStream] — the stream that embeds this state machine.
/// - [ReceiveStateMachine] — the corresponding receive-side state machine.
/// - RFC 9000 Section 3.1 — QUIC stream states.
class SendStateMachine {
  SendStreamState _state = SendStreamState.ready;

  /// The current state of the send side.
  SendStreamState get state => _state;

  /// Whether the stream has reached a terminal state.
  ///
  /// Terminal states are [SendStreamState.received] and
  /// [SendStreamState.resetReceived].
  bool get isTerminal =>
      _state == SendStreamState.received ||
      _state == SendStreamState.resetReceived;

  /// Whether the stream is allowed to send new data.
  ///
  /// Returns `true` when in [SendStreamState.ready] or [SendStreamState.send].
  bool get canSend =>
      _state == SendStreamState.ready || _state == SendStreamState.send;

  /// Whether the stream has been or is being reset.
  ///
  /// Returns `true` when in [SendStreamState.resetSent] or
  /// [SendStreamState.resetReceived].
  bool get wasReset =>
      _state == SendStreamState.resetSent ||
      _state == SendStreamState.resetReceived;

  /// Valid transitions:
  /// ready → send (on first data sent)
  /// send → sent (on all data sent with FIN)
  /// sent → received (on ACK of all data)
  /// ready/send → resetSent (on RESET_STREAM sent)
  /// resetSent → resetReceived (on ACK of RESET_STREAM)
  /// send → resetSent (on abort)
  void transitionTo(SendStreamState newState) {
    if (_state == newState) return;

    switch (_state) {
      case SendStreamState.ready:
        if (newState == SendStreamState.send ||
            newState == SendStreamState.resetSent) {
          _state = newState;
          return;
        }
        break;
      case SendStreamState.send:
        if (newState == SendStreamState.sent ||
            newState == SendStreamState.resetSent) {
          _state = newState;
          return;
        }
        break;
      case SendStreamState.sent:
        if (newState == SendStreamState.received ||
            newState == SendStreamState.resetSent) {
          _state = newState;
          return;
        }
        break;
      case SendStreamState.resetSent:
        if (newState == SendStreamState.resetReceived) {
          _state = newState;
          return;
        }
        break;
      case SendStreamState.received:
      case SendStreamState.resetReceived:
        break;
    }

    throw StateError('Invalid transition from $_state to $newState');
  }

  /// Notify that data has been sent.
  void onDataSent() => transitionTo(SendStreamState.send);

  /// Notify that all data including FIN has been sent.
  void onFinSent() => transitionTo(SendStreamState.sent);

  /// Notify that all data has been acknowledged.
  void onAllDataAcked() => transitionTo(SendStreamState.received);

  /// Notify that RESET_STREAM was sent.
  void onResetSent() => transitionTo(SendStreamState.resetSent);

  /// Notify that RESET_STREAM was acknowledged.
  void onResetAcked() => transitionTo(SendStreamState.resetReceived);

  /// Notify that STOP_SENDING was received from peer.
  void onStopSendingReceived() => transitionTo(SendStreamState.resetSent);
}

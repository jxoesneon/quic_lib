enum SendStreamState {
  ready,
  send,
  sent,
  received, // data acked (terminal success)
  resetSent,
  resetReceived, // terminal aborted
}

class SendStateMachine {
  SendStreamState _state = SendStreamState.ready;

  SendStreamState get state => _state;
  bool get isTerminal =>
      _state == SendStreamState.received || _state == SendStreamState.resetReceived;
  bool get canSend =>
      _state == SendStreamState.ready || _state == SendStreamState.send;
  bool get wasReset =>
      _state == SendStreamState.resetSent || _state == SendStreamState.resetReceived;

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

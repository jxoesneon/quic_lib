/// Lifecycle states for the receiving half of a QUIC stream (RFC 9000 Section 3.2).
///
/// Mirrors [SendStreamState] for the receiver. The stream starts in [recv]
/// and progresses toward the terminal states [dataRead] (all bytes consumed
/// by the application) or [resetRead] (peer-initiated abort acknowledged).
///
/// See also:
/// - [ReceiveStateMachine] — manages transitions between these states.
/// - [SendStreamState] — the corresponding send-side states.
/// - RFC 9000 Section 3.2 — receiving-side stream states.
enum ReceiveStreamState {
  /// Receiving data; final size not yet known.
  recv,

  /// FIN received or RESET_STREAM received; final size is now known.
  sizeKnown,

  /// All data up to final size has been received.
  dataReceived,

  /// Application has read all data up to final size.
  dataRead,

  /// RESET_STREAM frame received from peer.
  resetReceived,

  /// Application has read the reset indication.
  resetRead,
}

/// State machine for the receive side of a QUIC stream (RFC 9000 Section 3.2).
///
/// [ReceiveStateMachine] tracks how much data has been received and whether
/// the stream has been fully consumed or aborted. It enforces valid state
/// transitions and performs security checks (e.g., rejecting data that
/// exceeds the declared final size).
///
/// ## Example
/// ```dart
/// final sm = ReceiveStateMachine();
/// sm.onDataReceived(fin: true, finalSize: 1024, bytesReceived: 1024);
/// sm.onAllDataReceived();
/// sm.onDataRead();
/// assert(sm.isTerminal);
/// ```
///
/// See also:
/// - [ReceiveStreamState] — the individual states this machine tracks.
/// - [SendStateMachine] — the corresponding send-side state machine.
/// - RFC 9000 Section 3.2 — receiving-side stream states.
class ReceiveStateMachine {
  /// Creates a receive-side stream state machine in [ReceiveStreamState.recv].
  ReceiveStateMachine();

  ReceiveStreamState _state = ReceiveStreamState.recv;
  int? _finalSize;

  /// The current state of the receive side.
  ReceiveStreamState get state => _state;

  /// Whether the stream has reached a terminal state.
  ///
  /// Terminal states are [ReceiveStreamState.dataRead] and
  /// [ReceiveStreamState.resetRead].
  bool get isTerminal =>
      _state == ReceiveStreamState.dataRead ||
      _state == ReceiveStreamState.resetRead;

  /// Whether the stream can still accept incoming data.
  ///
  /// Returns `true` when in [ReceiveStreamState.recv] or
  /// [ReceiveStreamState.sizeKnown].
  bool get canReceive =>
      _state == ReceiveStreamState.recv ||
      _state == ReceiveStreamState.sizeKnown;

  /// Whether the stream was reset by the peer.
  ///
  /// Returns `true` when in [ReceiveStreamState.resetReceived] or
  /// [ReceiveStreamState.resetRead].
  bool get wasReset =>
      _state == ReceiveStreamState.resetReceived ||
      _state == ReceiveStreamState.resetRead;

  /// The final byte size of the stream, if known.
  ///
  /// Set when a STREAM frame with the FIN bit or a RESET_STREAM frame is
  /// received. `null` until then.
  int? get finalSize => _finalSize;

  /// Cumulative bytes received on this stream.
  int get bytesReceived => _bytesReceived;
  int _bytesReceived = 0;

  /// Record incoming data.
  ///
  /// [bytesReceived] is the cumulative total of bytes delivered so far.
  /// [fin] and [finalSize] come from the STREAM frame header.
  ///
  /// Throws [StateError] if the declared [finalSize] is inconsistent with
  /// data already received, or if [bytesReceived] exceeds [finalSize].
  void onDataReceived(
      {bool fin = false, int? finalSize, int bytesReceived = 0}) {
    if (bytesReceived < 0) bytesReceived = 0;
    _bytesReceived = bytesReceived;

    if (finalSize != null) {
      // SECURITY: finalSize cannot be less than data already received.
      if (_bytesReceived > finalSize) {
        throw StateError(
          'Final size $finalSize is less than already received $_bytesReceived bytes',
        );
      }
      _setFinalSize(finalSize);
    }

    // SECURITY: reject data that exceeds the known final size.
    if (_finalSize != null && _bytesReceived > _finalSize!) {
      throw StateError(
          'Received $_bytesReceived bytes exceeds final size $_finalSize');
    }

    if (_state == ReceiveStreamState.recv) {
      if (fin) {
        _state = ReceiveStreamState.sizeKnown;
      }
      // otherwise stay in recv
    }
  }

  /// Notifies that all bytes up to [finalSize] have been received.
  ///
  /// Transitions from [ReceiveStreamState.recv] or
  /// [ReceiveStreamState.sizeKnown] to [ReceiveStreamState.dataReceived].
  /// This should be called once the reassembler confirms there are no gaps
  /// in the received byte sequence.
  void onAllDataReceived() {
    if (_state == ReceiveStreamState.recv ||
        _state == ReceiveStreamState.sizeKnown) {
      _state = ReceiveStreamState.dataReceived;
    }
  }

  /// Notifies that the application has consumed all stream data.
  ///
  /// Transitions from [ReceiveStreamState.dataReceived] to
  /// [ReceiveStreamState.dataRead] (terminal success state).
  ///
  /// Throws [StateError] if called from any state other than
  /// [ReceiveStreamState.dataReceived].
  void onDataRead() {
    if (_state == ReceiveStreamState.dataReceived) {
      _state = ReceiveStreamState.dataRead;
    } else {
      throw StateError('Cannot read data from state $_state');
    }
  }

  /// Notifies that a RESET_STREAM frame was received from the peer.
  ///
  /// Transitions from [ReceiveStreamState.recv],
  /// [ReceiveStreamState.sizeKnown], or [ReceiveStreamState.dataReceived]
  /// to [ReceiveStreamState.resetReceived]. If the stream is already in a
  /// more advanced state, the reset is silently ignored.
  void onResetReceived() {
    if (_state == ReceiveStreamState.recv ||
        _state == ReceiveStreamState.sizeKnown ||
        _state == ReceiveStreamState.dataReceived) {
      _state = ReceiveStreamState.resetReceived;
    }
  }

  /// Notifies that the application has acknowledged the peer-initiated reset.
  ///
  /// Transitions from [ReceiveStreamState.resetReceived] to
  /// [ReceiveStreamState.resetRead] (terminal aborted state).
  ///
  /// Throws [StateError] if called from any state other than
  /// [ReceiveStreamState.resetReceived].
  void onResetRead() {
    if (_state == ReceiveStreamState.resetReceived) {
      _state = ReceiveStreamState.resetRead;
    } else {
      throw StateError('Cannot read reset from state $_state');
    }
  }

  void _setFinalSize(int size) {
    if (_finalSize != null && _finalSize != size) {
      throw StateError(
          'Final size already set to $_finalSize, cannot change to $size');
    }
    _finalSize = size;
  }
}

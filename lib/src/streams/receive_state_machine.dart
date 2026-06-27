/// QUIC receive-side stream states per RFC 9000 Section 3.2.
enum ReceiveStreamState {
  recv,
  sizeKnown,
  dataReceived,
  dataRead,
  resetReceived,
  resetRead,
}

/// State machine for the receive side of a QUIC stream.
class ReceiveStateMachine {
  ReceiveStreamState _state = ReceiveStreamState.recv;
  int? _finalSize;

  ReceiveStreamState get state => _state;

  bool get isTerminal =>
      _state == ReceiveStreamState.dataRead ||
      _state == ReceiveStreamState.resetRead;

  bool get canReceive =>
      _state == ReceiveStreamState.recv ||
      _state == ReceiveStreamState.sizeKnown;

  bool get wasReset =>
      _state == ReceiveStreamState.resetReceived ||
      _state == ReceiveStreamState.resetRead;

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
  void onDataReceived({bool fin = false, int? finalSize, int bytesReceived = 0}) {
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
      throw StateError('Received $_bytesReceived bytes exceeds final size $_finalSize');
    }

    if (_state == ReceiveStreamState.recv) {
      if (fin) {
        _state = ReceiveStreamState.sizeKnown;
      }
      // otherwise stay in recv
    }
  }

  void onAllDataReceived() {
    if (_state == ReceiveStreamState.recv || _state == ReceiveStreamState.sizeKnown) {
      _state = ReceiveStreamState.dataReceived;
    }
  }

  void onDataRead() {
    if (_state == ReceiveStreamState.dataReceived) {
      _state = ReceiveStreamState.dataRead;
    } else {
      throw StateError('Cannot read data from state $_state');
    }
  }

  void onResetReceived() {
    if (_state == ReceiveStreamState.recv ||
        _state == ReceiveStreamState.sizeKnown ||
        _state == ReceiveStreamState.dataReceived) {
      _state = ReceiveStreamState.resetReceived;
    }
  }

  void onResetRead() {
    if (_state == ReceiveStreamState.resetReceived) {
      _state = ReceiveStreamState.resetRead;
    } else {
      throw StateError('Cannot read reset from state $_state');
    }
  }

  void _setFinalSize(int size) {
    if (_finalSize != null && _finalSize != size) {
      throw StateError('Final size already set to $_finalSize, cannot change to $size');
    }
    _finalSize = size;
  }
}

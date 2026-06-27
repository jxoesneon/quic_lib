/// QUIC flow controller for connection-level and stream-level flow control.
class FlowController {
  // SECURITY: Cap window to prevent unbounded growth / integer issues.
  static const int maxWindow = 256 * 1024 * 1024; // 256 MB

  int _maxData;
  int _consumed = 0;
  int _advertisedLimit;
  int _nextLimit;

  FlowController({required int initialLimit})
      : _maxData = initialLimit,
        _advertisedLimit = initialLimit,
        _nextLimit = initialLimit;

  /// Bytes remaining in the current window.
  int get availableWindow => _maxData - _consumed;

  /// True if the window is exhausted.
  bool get isBlocked => availableWindow <= 0;

  /// Consume [bytes] from the window.
  void consume(int bytes) {
    // SECURITY: Reject negative values that would inflate the window.
    if (bytes < 0) {
      throw ArgumentError('bytes must be non-negative, got $bytes');
    }
    _consumed += bytes;
  }

  /// Update the peer's max data limit (received via MAX_DATA/MAX_STREAM_DATA).
  void updateLimit(int newLimit) {
    if (newLimit > _maxData) {
      _maxData = newLimit > maxWindow ? maxWindow : newLimit;
    }
  }

  /// Check if we should send a window update.
  /// Returns the new limit if an update is needed, null otherwise.
  int? shouldUpdateWindow({int threshold = 0}) {
    if (_consumed >= _advertisedLimit - threshold) {
      _nextLimit = _advertisedLimit * 2;
      if (_nextLimit > maxWindow) _nextLimit = maxWindow;
      return _nextLimit;
    }
    return null;
  }

  /// Advertise a new limit that was sent to the peer.
  void onLimitSent(int limit) {
    _advertisedLimit = limit;
  }

  /// Reset state.
  void reset() {
    _consumed = 0;
    _maxData = _advertisedLimit;
  }
}

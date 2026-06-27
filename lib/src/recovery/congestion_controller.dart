/// NewReno congestion controller per RFC 9002 Section 7.
///
/// Implements slow start, congestion avoidance, and recovery.
class CongestionController {
  /// Initial congestion window in bytes (RFC 9002: 2 * max_datagram_size, default 1200).
  static const int initialWindow = 2400;

  /// Minimum congestion window in bytes.
  static const int minimumWindow = 2400;

  static const int _maxDatagramSize = 1200;

  int _congestionWindow = initialWindow;
  int _ssthresh = -1; // -1 means no threshold (always in slow start).
  int _bytesInFlight = 0;
  int _congestionRecoveryStartTime = -1; // -1 means not in recovery.

  /// Current congestion window in bytes.
  int get congestionWindow => _congestionWindow;

  /// Slow start threshold. -1 means no threshold (always in slow start).
  int get ssthresh => _ssthresh;

  /// Whether in slow start.
  bool get inSlowStart => _ssthresh < 0 || _congestionWindow < _ssthresh;

  /// Whether in recovery.
  bool get inRecovery => _congestionRecoveryStartTime >= 0;

  /// Bytes in flight.
  int get bytesInFlight => _bytesInFlight;

  /// Register a packet as sent (adds to bytes_in_flight).
  void onPacketSent(int bytes) {
    // SECURITY: Reject negative byte counts.
    if (bytes < 0) bytes = 0;
    _bytesInFlight += bytes;
  }

  /// Process an ACK.
  void onAckReceived(int ackedBytes) {
    // SECURITY: Reject negative ackedBytes to prevent integer underflow.
    if (ackedBytes < 0) ackedBytes = 0;

    // Remove acknowledged bytes from bytes in flight.
    _bytesInFlight -= ackedBytes;
    if (_bytesInFlight < 0) {
      _bytesInFlight = 0;
    }

    // Do not increase cwnd during recovery.
    if (inRecovery) {
      return;
    }

    // SECURITY: Cap cwnd growth to prevent 64-bit integer overflow.
    const maxCwnd = 0x3FFFFFFFFFFFFFFF;
    if (inSlowStart) {
      // Slow start: cwnd += acked_bytes.
      if (_congestionWindow > maxCwnd - ackedBytes) {
        _congestionWindow = maxCwnd;
      } else {
        _congestionWindow += ackedBytes;
      }
    } else {
      // Congestion avoidance: cwnd += max_datagram_size * acked_bytes / cwnd.
      final growth = (_maxDatagramSize * ackedBytes) ~/ _congestionWindow;
      if (_congestionWindow > maxCwnd - growth) {
        _congestionWindow = maxCwnd;
      } else {
        _congestionWindow += growth;
      }
    }
  }

  /// Enter recovery (on loss detection).
  void onCongestionEvent(int timeUs) {
    if (inRecovery) {
      // Already in recovery; do not reduce cwnd again until exit.
      return;
    }
    _congestionRecoveryStartTime = timeUs;
    _ssthresh = _congestionWindow ~/ 2;
    _congestionWindow = _ssthresh > minimumWindow ? _ssthresh : minimumWindow;
  }

  /// Exit recovery (RFC 9002 §7.3.2).
  void onRecoveryExit() {
    _congestionRecoveryStartTime = -1;
  }

  /// Can we send [bytes]?
  bool canSend(int bytes) {
    return _bytesInFlight + bytes <= _congestionWindow;
  }

  /// Reset to initial state.
  void reset() {
    _congestionWindow = initialWindow;
    _ssthresh = -1;
    _bytesInFlight = 0;
    _congestionRecoveryStartTime = -1;
  }
}

import 'rtt_estimator.dart';

/// QUIC Probe Timeout (PTO) scheduler per RFC 9002 Section 6.2.
///
/// Manages the exponential backoff timer used to send probe packets
/// when an ACK is not received in time.
class PtoScheduler {
  final RttEstimator _rttEstimator;
  int _ptoCount = 0;
  int? _lastPtoTime;

  PtoScheduler(this._rttEstimator);

  /// Compute the current PTO duration in microseconds.
  ///
  /// Base PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
  /// Then multiplied by 2^pto_count for exponential backoff.
  int get currentPtoUs {
    final basePto = _rttEstimator.getPtoDuration();
    return basePto * (1 << _ptoCount);
  }

  /// Check if PTO has expired based on current time.
  ///
  /// Returns true when [currentTimeUs] - _lastPtoTime >= currentPtoUs.
  /// Returns false if the timer has not been armed.
  bool isExpired(int currentTimeUs) {
    final lastTime = _lastPtoTime;
    if (lastTime == null) return false;
    return currentTimeUs - lastTime >= currentPtoUs;
  }

  /// Call when a PTO fires.
  ///
  /// Increments [ptoCount] (capped to prevent exponential overflow) and records
  /// the current time so the next PTO check uses the updated backoff multiplier.
  void onPtoFired(int currentTimeUs) {
    // SECURITY: Cap backoff to prevent 64-bit integer overflow (1 << 63).
    if (_ptoCount < 10) {
      _ptoCount++;
    }
    _lastPtoTime = currentTimeUs;
  }

  /// Reset PTO count (e.g., on ACK receipt).
  ///
  /// Clears the exponential backoff and disarms the timer reference
  /// so the caller must re-arm it.
  void onAckReceived() {
    _ptoCount = 0;
    _lastPtoTime = null;
  }

  /// Reset everything.
  void reset() {
    _ptoCount = 0;
    _lastPtoTime = null;
  }

  /// Current PTO count (for debugging).
  int get ptoCount => _ptoCount;
}

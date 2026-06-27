/// QUIC RTT Estimator per RFC 9002 Section 5.
class RttEstimator {
  static const int kInitialRttUs = 333000; // 333 ms
  static const int kGranularity = 1000; // 1 ms

  // SECURITY: Cap RTT and ACK delay to prevent unbounded BigInt growth.
  static const int maxRttUs = 60000000; // 60 seconds
  static const int maxAckDelayUs = 16383 * 1000; // max QUIC ACK delay (~16s)

  int _smoothedRtt;
  int _rttVar;
  int _minRtt;
  int _latestRtt;
  bool _hasSample;

  /// Maximum ACK delay from peer in microseconds.
  int _maxAckDelay;

  RttEstimator()
      : _smoothedRtt = kInitialRttUs,
        _rttVar = kInitialRttUs ~/ 2,
        _minRtt = kInitialRttUs,
        _latestRtt = kInitialRttUs,
        _maxAckDelay = 25000, // 25 ms default for Application Data
        _hasSample = false;

  /// Smoothed RTT in microseconds.
  int get smoothedRtt => _smoothedRtt;

  /// RTT variation in microseconds.
  int get rttVar => _rttVar;

  /// Minimum RTT observed in microseconds.
  int get minRtt => _minRtt;

  /// Latest RTT sample in microseconds.
  int get latestRtt => _latestRtt;

  /// Maximum ACK delay from peer in microseconds.
  int get maxAckDelay => _maxAckDelay;

  set maxAckDelay(int value) {
    _maxAckDelay = value < 0
        ? 0
        : (value > maxAckDelayUs ? maxAckDelayUs : value);
  }

  /// Update with a new RTT sample.
  /// [ackDelay] is the peer's reported ACK delay in microseconds.
  /// [isHandshake] is true if this sample is from handshake packets.
  void update(int latestRttUs, {int ackDelay = 0, bool isHandshake = false}) {
    // SECURITY: Clamp RTT to valid range.
    if (latestRttUs < 0) latestRttUs = 0;
    if (latestRttUs > maxRttUs) latestRttUs = maxRttUs;

    _latestRtt = latestRttUs;

    if (!_hasSample) {
      _smoothedRtt = latestRttUs;
      _rttVar = latestRttUs ~/ 2;
      _minRtt = latestRttUs;
      _hasSample = true;
      return;
    }

    // Update min_rtt with the raw sample.
    if (latestRttUs < _minRtt) {
      _minRtt = latestRttUs;
    }

    final ackDelayUsed = ackDelay < maxAckDelay ? ackDelay : maxAckDelay;

    // Compute adjusted_rtt per RFC 9002 Section 5.3.
    // ack_delay is NOT subtracted when the sample equals min_rtt.
    final int adjustedRtt;
    if (latestRttUs - _minRtt >= ackDelayUsed) {
      adjustedRtt = latestRttUs - ackDelayUsed;
    } else {
      adjustedRtt = latestRttUs;
    }

    // EWMA updates with single rounding to minimize truncation error.
    _rttVar = ((3 * _rttVar) + (_smoothedRtt - adjustedRtt).abs()) ~/ 4;
    _smoothedRtt = ((7 * _smoothedRtt) + adjustedRtt) ~/ 8;
  }

  /// Get the PTO duration in microseconds.
  /// pto = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
  int getPtoDuration() {
    final varComponent = (_rttVar * 4 > kGranularity) ? _rttVar * 4 : kGranularity;
    return _smoothedRtt + varComponent + maxAckDelay;
  }

  /// Reset to initial values.
  void reset() {
    _smoothedRtt = kInitialRttUs;
    _rttVar = kInitialRttUs ~/ 2;
    _minRtt = kInitialRttUs;
    _latestRtt = kInitialRttUs;
    _maxAckDelay = 25000;
    _hasSample = false;
  }
}

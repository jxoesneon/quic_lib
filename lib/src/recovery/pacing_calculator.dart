/// QUIC packet pacing calculator.
///
/// Computes the pacing rate and interval based on smoothed RTT and the
/// current congestion window, as described in RFC 9002 Section 7.7.
class PacingCalculator {
  /// Smoothed RTT in microseconds.
  int _smoothedRttUs;

  /// Congestion window in bytes.
  int _congestionWindow;

  /// Packet size in bytes (default 1200).
  final int packetSize;

  PacingCalculator({
    int smoothedRttUs = 333000,
    int congestionWindow = 2400,
    this.packetSize = 1200,
  })  : _smoothedRttUs = smoothedRttUs,
        _congestionWindow = congestionWindow;

  /// Pacing rate in bytes per microsecond.
  double get pacingRate {
    if (_smoothedRttUs <= 0) return 0.0;
    return _congestionWindow / _smoothedRttUs;
  }

  /// Time to wait between packets in microseconds.
  int get pacingIntervalUs {
    if (_congestionWindow <= 0 || _smoothedRttUs <= 0) return 0;
    return (packetSize * _smoothedRttUs) ~/ _congestionWindow;
  }

  /// Whether pacing is needed (RFC: pace when cwnd > 2*packet_size).
  bool get shouldPace => _congestionWindow > 2 * packetSize;

  /// Update RTT.
  void updateRtt(int smoothedRttUs) {
    _smoothedRttUs = smoothedRttUs;
  }

  /// Update congestion window.
  void updateCongestionWindow(int cwnd) {
    _congestionWindow = cwnd;
  }

  /// Reset to default values.
  void reset() {
    _smoothedRttUs = 333000;
    _congestionWindow = 2400;
  }
}

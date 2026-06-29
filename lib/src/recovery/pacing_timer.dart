/// QUIC packet pacing timer.
///
/// Tracks the last time a packet was released and enforces a minimum interval
/// between subsequent non-ACK-only packets, as recommended by RFC 9002
/// Section 7.7. ACK-only packets are not paced because they do not contribute
/// to congestion.
class PacingTimer {
  final int Function() _clockUs;
  int? _lastSendTimeUs;

  /// Creates a pacing timer.
  ///
  /// [clockUs] can be injected for tests; otherwise the wall clock is used.
  PacingTimer({int Function()? clockUs})
      : _clockUs = clockUs ?? _defaultClockUs;

  static int _defaultClockUs() => DateTime.now().microsecondsSinceEpoch;

  /// Returns the remaining microseconds that must elapse before the next
  /// packet may be sent, or 0 if it may be sent immediately.
  ///
  /// On the first call, the timer is initialized to allow an immediate send
  /// and the current time is recorded as the last send time.
  int timeUntilNextSend(int pacingIntervalUs) {
    if (pacingIntervalUs <= 0) return 0;
    final now = _clockUs();
    final last = _lastSendTimeUs;
    if (last == null) {
      _lastSendTimeUs = now;
      return 0;
    }
    final elapsed = now - last;
    if (elapsed >= pacingIntervalUs) {
      _lastSendTimeUs = now;
      return 0;
    }
    return pacingIntervalUs - elapsed;
  }

  /// Record that a packet was sent at the current time.
  void recordSend() {
    _lastSendTimeUs = _clockUs();
  }
}

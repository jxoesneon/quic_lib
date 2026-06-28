/// Hystart++ / basic Hystart helper for early slow-start exit.
///
/// Implements two detection mechanisms from RFC 8312 Appendix B:
/// 1. ACK train length: exit if a burst of consecutive ACKs exceeds a threshold.
/// 2. Delay-based: exit if the spacing between consecutive ACKs increases
///    significantly, indicating growing queuing delay.
class Hystart {
  static const int _ackTrainThreshold = 8;
  static const int _ackTrainMaxGapUs = 2000; // 2 ms
  static const int _spacingIncreaseFactor = 2;

  DateTime? _lastAckTime;
  int? _lastSpacingUs;
  int _trainCount = 0;
  bool _exitSlowStart = false;

  /// Whether Hystart has signaled that slow start should exit.
  bool get shouldExitSlowStart => _exitSlowStart;

  /// Process an ACK at [ackTime].
  ///
  /// [largestAcked] is the largest packet number acknowledged by this ACK.
  void onAck(int largestAcked, DateTime ackTime) {
    if (_exitSlowStart) return;

    if (_lastAckTime != null) {
      final spacingUs = ackTime.difference(_lastAckTime!).inMicroseconds;

      // Delay-based exit: spacing increased significantly.
      if (_lastSpacingUs != null &&
          _lastSpacingUs! > 0 &&
          spacingUs > _lastSpacingUs! * _spacingIncreaseFactor) {
        _exitSlowStart = true;
        return;
      }
      _lastSpacingUs = spacingUs;

      // ACK train: consecutive ACKs close together.
      if (spacingUs < _ackTrainMaxGapUs) {
        _trainCount++;
      } else {
        _trainCount = 1;
      }
    } else {
      _trainCount = 1;
    }

    if (_trainCount >= _ackTrainThreshold) {
      _exitSlowStart = true;
      return;
    }

    _lastAckTime = ackTime;
  }

  /// Reset Hystart state (e.g. on congestion event or connection migration).
  void reset() {
    _lastAckTime = null;
    _lastSpacingUs = null;
    _trainCount = 0;
    _exitSlowStart = false;
  }
}

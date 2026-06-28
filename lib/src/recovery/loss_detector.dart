/// QUIC loss detector per RFC 9002 Section 6.
class LossDetector {
  /// Largest sent packet number that has been acked.
  int get largestAcked => _largestAcked;
  int _largestAcked = -1;

  /// Time threshold for loss detection: kTimeThreshold = 9/8.
  static const double timeThreshold = 9.0 / 8.0;

  /// Packet threshold for loss detection: kPacketThreshold = 3.
  static const int packetThreshold = 3;

  /// Timer granularity in microseconds.
  static const int kGranularity = 1000;

  // SECURITY: Max tracked packets to prevent memory exhaustion DoS.
  static const int maxTrackedPackets = 10000;

  final Map<int, int> _sentTimes = {};

  /// Register a sent packet.
  void onPacketSent(int packetNumber, int sentTimeUs,
      {bool ackEliciting = true}) {
    // SECURITY: Reject negative packet numbers.
    if (packetNumber < 0) return;
    if (ackEliciting) {
      // SECURITY: Reject if tracking capacity exceeded.
      if (_sentTimes.length >= maxTrackedPackets) {
        throw StateError(
            'LossDetector: max tracked packets ($maxTrackedPackets) exceeded');
      }
      _sentTimes[packetNumber] = sentTimeUs;
    }
  }

  /// Process an ACK frame and return lost packet numbers.
  List<int> onAckReceived(
      int largestAcked, int ackReceiveTimeUs, int smoothedRttUs) {
    // SECURITY: Reject negative largestAcked.
    if (largestAcked < 0) largestAcked = -1;
    _largestAcked = largestAcked;
    final lost = <int>[];

    for (final entry in _sentTimes.entries.toList()) {
      final pn = entry.key;
      final sentTime = entry.value;

      if (pn <= largestAcked) {
        // ACKed, remove from tracking
        _sentTimes.remove(pn);
        continue;
      }

      if (isPacketLostByThreshold(pn, largestAcked) ||
          isPacketLostByTime(pn, sentTime, ackReceiveTimeUs, smoothedRttUs)) {
        lost.add(pn);
        _sentTimes.remove(pn);
      }
    }

    return lost;
  }

  /// Check if a specific packet is lost based on packet threshold.
  bool isPacketLostByThreshold(int packetNumber, int largestAcked) {
    return largestAcked - packetNumber >= packetThreshold;
  }

  /// Check if a packet is lost based on time threshold.
  bool isPacketLostByTime(int packetNumber, int sentTimeUs,
      int ackReceiveTimeUs, int smoothedRttUs) {
    final thresholdUs = (timeThreshold * smoothedRttUs).toInt() + kGranularity;
    return sentTimeUs < ackReceiveTimeUs - thresholdUs;
  }

  /// Reset state.
  void reset() {
    _largestAcked = -1;
    _sentTimes.clear();
  }
}

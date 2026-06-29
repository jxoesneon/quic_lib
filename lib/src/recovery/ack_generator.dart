import '../wire/frame.dart';

/// Internal helper for a contiguous packet-number range.
class _IntRange {
  final int largest;
  final int smallest;
  _IntRange(this.largest, this.smallest);
}

/// Policy state derived from ACK_FREQUENCY frames (RFC 9298).
///
/// Controls when the endpoint should send ACK frames based on
/// peer-requested parameters.
class AckFrequencyPolicy {
  /// Sequence number of the most recently processed ACK_FREQUENCY frame.
  int _sequenceNumber = -1;

  /// Number of ack-eliciting packets after which an ACK must be sent.
  /// 0 or 1 means acknowledge every ack-eliciting packet.
  int _ackElicitingThreshold = 1;

  /// Maximum ACK delay the receiver should use (in microseconds).
  int _maxAckDelayUs = 25000; // default 25ms per RFC 9000

  /// Whether the receiver may ignore out-of-order packets when deciding
  /// to send an immediate ACK.
  bool _ignoreOrder = false;

  /// Count of ack-eliciting packets received since last ACK.
  int _ackElicitingReceived = 0;

  /// Process an incoming ACK_FREQUENCY frame.
  ///
  /// Returns `true` if the frame was accepted (sequence number is new).
  bool processAckFrequencyFrame(AckFrequencyFrame frame) {
    if (frame.sequenceNumber <= _sequenceNumber) {
      return false; // stale frame, ignore per RFC 9298
    }
    _sequenceNumber = frame.sequenceNumber;
    _ackElicitingThreshold = frame.requestedAckElicitingThreshold;
    _maxAckDelayUs = frame.requestedMaxAckDelay;
    _ignoreOrder = frame.ignoreOrder;
    return true;
  }

  /// Notify the policy that an ack-eliciting packet was received.
  void onAckElicitingPacketReceived() {
    _ackElicitingReceived++;
  }

  /// Check whether an ACK should be sent immediately based on threshold.
  bool shouldAckImmediately() {
    if (_ackElicitingThreshold <= 1) return true;
    return _ackElicitingReceived >= _ackElicitingThreshold;
  }

  /// Reset the counter after an ACK has been sent.
  void onAckSent() {
    _ackElicitingReceived = 0;
  }

  int get maxAckDelayUs => _maxAckDelayUs;
  bool get ignoreOrder => _ignoreOrder;
  int get sequenceNumber => _sequenceNumber;
}

/// Generates ACK frames based on received packets.
///
/// Implements ACK range tracking per RFC 9000 Section 13.2.1
/// and ACK_FREQUENCY policy per RFC 9298.
class AckGenerator {
  int _largestAcked = -1;
  int _largestAckReceivedTime = 0;
  final Set<int> _receivedPackets = {};

  /// Maximum number of ACK ranges for DoS protection.
  static const int _maxAckRanges = 256;

  /// ACK_FREQUENCY policy state.
  final AckFrequencyPolicy _frequencyPolicy = AckFrequencyPolicy();

  /// Time (in microseconds) when the largest acked packet was received.
  int get largestAckReceivedTime => _largestAckReceivedTime;

  /// Current ACK_FREQUENCY policy.
  AckFrequencyPolicy get frequencyPolicy => _frequencyPolicy;

  /// Acknowledge a received packet.
  void onPacketReceived(int packetNumber, int receiveTimeUs,
      {bool isAckEliciting = true}) {
    if (packetNumber > _largestAcked) {
      _largestAcked = packetNumber;
      _largestAckReceivedTime = receiveTimeUs;
    }
    _receivedPackets.add(packetNumber);
    if (isAckEliciting) {
      _frequencyPolicy.onAckElicitingPacketReceived();
    }
  }

  /// Build an ACK frame from current state.
  ///
  /// Resets the ACK_FREQUENCY packet counter so that the next ACK
  /// is only sent once the threshold is reached again.
  AckFrame buildAckFrame({int ackDelayUs = 0}) {
    _frequencyPolicy.onAckSent();
    final ranges = _computeAckRanges();
    return AckFrame(
      largestAcknowledged: _largestAcked,
      ackDelay: ackDelayUs,
      ackRanges: ranges,
    );
  }

  List<AckRange> _computeAckRanges() {
    if (_largestAcked < 0 || _receivedPackets.isEmpty) {
      return [];
    }

    // Sort received packets descending.
    final sorted = _receivedPackets.toList()..sort((a, b) => b.compareTo(a));
    final ranges = <_IntRange>[];

    // Build contiguous ranges in descending order.
    var rangeLargest = sorted.first;
    var rangeSmallest = sorted.first;

    for (var i = 1; i < sorted.length; i++) {
      final pn = sorted[i];
      if (pn == rangeSmallest - 1) {
        // Contiguous — extend the range.
        rangeSmallest = pn;
      } else {
        // Gap — finalize the current range.
        ranges.add(_IntRange(rangeLargest, rangeSmallest));
        if (ranges.length >= _maxAckRanges) {
          break;
        }
        rangeLargest = pn;
        rangeSmallest = pn;
      }
    }
    // Add the last range if we haven't hit the limit.
    if (ranges.length < _maxAckRanges) {
      ranges.add(_IntRange(rangeLargest, rangeSmallest));
    }

    // Convert to RFC 9000 ACK frame format:
    // - First range: gap=0, length = largest - smallest
    // - Subsequent: gap = prev_smallest - current_largest - 1,
    //                length = current_largest - current_smallest
    final result = <AckRange>[];
    for (var i = 0; i < ranges.length; i++) {
      final length = ranges[i].largest - ranges[i].smallest;
      if (i == 0) {
        result.add(AckRange(gap: 0, length: length));
      } else {
        final gap = ranges[i - 1].smallest - ranges[i].largest - 1;
        result.add(AckRange(gap: gap, length: length));
      }
    }
    return result;
  }

  /// Reset state.
  void reset() {
    _largestAcked = -1;
    _largestAckReceivedTime = 0;
    _receivedPackets.clear();
    _frequencyPolicy.onAckSent();
  }

  int get largestAcked => _largestAcked;
}

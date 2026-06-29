import '../wire/frame.dart';
import '../wire/transport_error_codes.dart';

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
  /// Maximum value for max_ack_delay in milliseconds (2^14 per RFC 9000 §18.2).
  static const int _maxAckDelayMs = 16384;

  /// Sequence number of the most recently processed ACK_FREQUENCY frame.
  int _sequenceNumber = -1;

  /// Number of ack-eliciting packets after which an ACK must be sent.
  /// 0 or 1 means acknowledge every ack-eliciting packet.
  int _ackElicitingThreshold = 1;

  /// Maximum ACK delay the receiver should use (in microseconds).
  int _maxAckDelayUs = 25000; // default 25ms per RFC 9000

  /// Reordering threshold for sending immediate ACKs on out-of-order packets.
  /// 0 means never ack out-of-order immediately; 1 is the default per RFC.
  int _reorderingThreshold = 1;

  /// Count of ack-eliciting packets received since last ACK.
  int _ackElicitingReceived = 0;

  /// Largest packet number received in the current key phase.
  int _largestReceived = -1;

  /// Process an incoming ACK_FREQUENCY frame.
  ///
  /// Validates values per RFC 9298:
  /// - requestedMaxAckDelay must be < 2^14 ms and >= [minAckDelayUs].
  /// - requestedAckElicitingThreshold must be non-negative.
  ///
  /// Returns `true` if the frame was accepted (sequence number is new).
  /// Throws [FrameEncodingError] for invalid values.
  bool processAckFrequencyFrame(AckFrequencyFrame frame,
      {int minAckDelayUs = 0}) {
    if (frame.sequenceNumber <= _sequenceNumber) {
      return false; // stale frame, ignore per RFC 9298
    }
    if (frame.requestedAckElicitingThreshold < 0) {
      throw FrameEncodingError('ACK_FREQUENCY threshold cannot be negative');
    }
    if (frame.requestedMaxAckDelay < 0 ||
        frame.requestedMaxAckDelay >= _maxAckDelayMs * 1000) {
      throw FrameEncodingError(
          'ACK_FREQUENCY requestedMaxAckDelay out of range');
    }
    if (frame.requestedMaxAckDelay < minAckDelayUs) {
      throw FrameEncodingError(
          'ACK_FREQUENCY requestedMaxAckDelay below min_ack_delay');
    }

    _sequenceNumber = frame.sequenceNumber;
    _ackElicitingThreshold = frame.requestedAckElicitingThreshold;
    _maxAckDelayUs = frame.requestedMaxAckDelay;
    _reorderingThreshold = frame.reorderingThreshold;
    return true;
  }

  /// Notify the policy that a packet was received.
  ///
  /// [packetNumber] is the packet number of the received packet.
  /// [isAckEliciting] is true if the packet contains ack-eliciting frames.
  /// Returns `true` if an immediate ACK should be sent because the packet
  /// is out of order and exceeds the reordering threshold.
  bool onPacketReceived(int packetNumber, {bool isAckEliciting = true}) {
    if (packetNumber > _largestReceived) {
      _largestReceived = packetNumber;
    } else if (_reorderingThreshold > 0) {
      final gap = _largestReceived - packetNumber;
      if (gap >= _reorderingThreshold) {
        return true;
      }
    }

    if (isAckEliciting) {
      _ackElicitingReceived++;
    }
    return false;
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

  /// Reset all policy state (e.g., on connection migration).
  void reset() {
    _sequenceNumber = -1;
    _ackElicitingThreshold = 1;
    _maxAckDelayUs = 25000;
    _reorderingThreshold = 1;
    _ackElicitingReceived = 0;
    _largestReceived = -1;
  }

  int get maxAckDelayUs => _maxAckDelayUs;
  int get reorderingThreshold => _reorderingThreshold;
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
  ///
  /// Returns `true` if an immediate ACK should be sent due to the
  /// ACK_FREQUENCY reordering threshold being exceeded.
  bool onPacketReceived(int packetNumber, int receiveTimeUs,
      {bool isAckEliciting = true}) {
    if (packetNumber > _largestAcked) {
      _largestAcked = packetNumber;
      _largestAckReceivedTime = receiveTimeUs;
    }
    _receivedPackets.add(packetNumber);
    return _frequencyPolicy.onPacketReceived(
      packetNumber,
      isAckEliciting: isAckEliciting,
    );
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
    _frequencyPolicy.reset();
  }

  int get largestAcked => _largestAcked;
}

import '../wire/frame.dart';

/// Internal helper for a contiguous packet-number range.
class _IntRange {
  final int largest;
  final int smallest;
  _IntRange(this.largest, this.smallest);
}

/// Generates ACK frames based on received packets.
///
/// Implements ACK range tracking per RFC 9000 Section 13.2.1.
class AckGenerator {
  int _largestAcked = -1;
  int _largestAckReceivedTime = 0;
  final Set<int> _receivedPackets = {};

  /// Maximum number of ACK ranges for DoS protection.
  static const int _maxAckRanges = 256;

  /// Time (in microseconds) when the largest acked packet was received.
  int get largestAckReceivedTime => _largestAckReceivedTime;

  /// Acknowledge a received packet.
  void onPacketReceived(int packetNumber, int receiveTimeUs) {
    if (packetNumber > _largestAcked) {
      _largestAcked = packetNumber;
      _largestAckReceivedTime = receiveTimeUs;
    }
    _receivedPackets.add(packetNumber);
  }

  /// Build an ACK frame from current state.
  AckFrame buildAckFrame({int ackDelayUs = 0}) {
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
  }

  int get largestAcked => _largestAcked;
}

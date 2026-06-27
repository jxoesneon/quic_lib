import '../wire/frame.dart';

/// Generates ACK frames based on received packets.
class AckGenerator {
  int _largestAcked = -1;
  int _largestAckReceivedTime = 0;
  final List<({int gap, int length})> _ackRanges = [];

  /// Time (in microseconds) when the largest acked packet was received.
  int get largestAckReceivedTime => _largestAckReceivedTime;

  /// Acknowledge a received packet.
  void onPacketReceived(int packetNumber, int receiveTimeUs) {
    if (packetNumber > _largestAcked) {
      _largestAcked = packetNumber;
      _largestAckReceivedTime = receiveTimeUs;
    }
    // Simplified: no range tracking for now
  }

  /// Build an ACK frame from current state.
  AckFrame buildAckFrame({int ackDelayUs = 0}) {
    return AckFrame(
      largestAcknowledged: _largestAcked,
      ackDelay: ackDelayUs,
      ackRanges: [],
    );
  }

  /// Reset state.
  void reset() {
    _largestAcked = -1;
    _largestAckReceivedTime = 0;
    _ackRanges.clear();
  }

  int get largestAcked => _largestAcked;
}

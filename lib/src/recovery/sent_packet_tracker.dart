/// Metadata for a sent packet used by [SentPacketTracker].
///
/// Tracks per-packet state required for loss detection, congestion control,
/// and RTT measurement. A packet is considered "in flight" if it has been
/// sent but not yet acked or declared lost.
class SentPacketInfo {
  /// Packet number in the packet number space.
  final int packetNumber;

  /// Timestamp when the packet was sent, in microseconds since epoch.
  final int sentTimeUs;

  /// Size of the packet on the wire, in bytes.
  final int sizeInBytes;

  /// Whether this packet elicits an ACK (false for ACK-only packets).
  final bool ackEliciting;

  /// Whether the packet is still in flight (sent but not acked or lost).
  final bool inFlight;

  /// List of frame type constants carried in this packet.
  final List<int> frames;

  /// Packet number space: 0=Initial, 1=Handshake, 2=Application Data.
  final int space;

  SentPacketInfo({
    required this.packetNumber,
    required this.sentTimeUs,
    required this.sizeInBytes,
    this.ackEliciting = true,
    this.inFlight = true,
    required this.frames,
    required this.space,
  });
}

/// Tracks sent packets per packet number space.
class SentPacketTracker {
  // SECURITY: Max packets per space to prevent memory exhaustion DoS.
  static const int maxPacketsPerSpace = 10000;

  final Map<int, Map<int, SentPacketInfo>> _spaces = {};
  final Map<int, int> _largestAcked = {};
  final Map<int, int> _highestSent = {};

  void track(SentPacketInfo info) {
    final spaceMap = _spaces.putIfAbsent(info.space, () => {});
    // SECURITY: Evict oldest packet if at capacity.
    if (spaceMap.length >= maxPacketsPerSpace) {
      final oldestPn = spaceMap.keys.reduce((a, b) => a < b ? a : b);
      spaceMap.remove(oldestPn);
    }
    spaceMap[info.packetNumber] = info;
    // Track highest sent for ACK validation.
    final currentHighest = _highestSent[info.space] ?? -1;
    if (info.packetNumber > currentHighest) {
      _highestSent[info.space] = info.packetNumber;
    }
  }

  /// Remove acknowledged packets and return info about acked packets.
  ///
  /// SECURITY: [largestAcked] is clamped to the highest sent packet number
  /// to prevent a malicious ACK from falsely acknowledging unsent packets.
  List<SentPacketInfo> onAck(
      int space, int largestAcked, List<({int gap, int length})> ackRanges) {
    // SECURITY: Validate space is a known packet number space.
    if (space < 0 || space > 2) {
      throw ArgumentError('Invalid packet number space: $space');
    }
    final spaceMap = _spaces[space];
    if (spaceMap == null) return [];

    // SECURITY: Clamp largestAcked to highest actually sent packet.
    final highestSent = _highestSent[space] ?? -1;
    if (largestAcked > highestSent) {
      largestAcked = highestSent;
    }

    final acked = <SentPacketInfo>[];

    // Build set of acked packet numbers from ACK ranges.
    final ackedSet = <int>{};

    if (ackRanges.isEmpty) {
      // Backward compatibility: ack everything <= largestAcked.
      for (final entry in spaceMap.entries.toList()) {
        if (entry.key <= largestAcked) {
          acked.add(entry.value);
          spaceMap.remove(entry.key);
        }
      }
    } else {
      var currentLargest = largestAcked;
      for (final range in ackRanges) {
        // Skip the gap before this range.
        currentLargest -= range.gap;
        // Ack [currentLargest - length, currentLargest]
        for (var pn = currentLargest;
            pn >= currentLargest - range.length && pn >= 0;
            pn--) {
          ackedSet.add(pn);
        }
        // Move to the packet before this range for the next gap.
        currentLargest -= range.length + 1;
      }
      // Remove acked packets from tracking.
      for (final pn in ackedSet.toList()) {
        final info = spaceMap.remove(pn);
        if (info != null) {
          acked.add(info);
        }
      }
    }

    if (largestAcked > (_largestAcked[space] ?? -1)) {
      _largestAcked[space] = largestAcked;
    }

    return acked;
  }

  /// Get all unacked in-flight packets in a space.
  List<SentPacketInfo> getUnackedPackets(int space) {
    final spaceMap = _spaces[space];
    if (spaceMap == null) return [];
    return spaceMap.values.where((info) => info.inFlight).toList();
  }

  /// Look up a specific packet's info in a space.
  SentPacketInfo? getPacketInfo(int space, int packetNumber) {
    final spaceMap = _spaces[space];
    if (spaceMap == null) return null;
    return spaceMap[packetNumber];
  }

  /// Get the largest acked packet in a space.
  int getLargestAcked(int space) => _largestAcked[space] ?? -1;

  /// Reset a space.
  void reset(int space) {
    _spaces.remove(space);
    _largestAcked.remove(space);
    _highestSent.remove(space);
  }

  /// Reset all spaces.
  void resetAll() {
    _spaces.clear();
    _largestAcked.clear();
    _highestSent.clear();
  }
}

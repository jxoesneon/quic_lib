/// QUIC packet number spaces per RFC 9000.
///
/// QUIC uses three distinct packet number spaces, each with independent
/// packet number sequences. This prevents retransmissions of a packet
/// in one space from being acknowledged by packets in another space.
enum PacketNumberSpace {
  initial(0),
  handshake(1),
  application(2);

  final int spaceIndex;
  const PacketNumberSpace(this.spaceIndex);
}

/// Manages packet number allocation, tracking of largest acknowledged,
/// and largest received packet numbers across all three QUIC packet
/// number spaces.
class PacketNumberSpaceManager {
  // SECURITY: Replay-protection window size (must be power of 2 for bitmask).
  static const int _replayWindowSize = 64;

  final Map<PacketNumberSpace, int> _nextPacketNumber = {};
  final Map<PacketNumberSpace, int> _largestAcked = {};
  final Map<PacketNumberSpace, int> _largestReceived = {};

  /// SECURITY: Per-space replay-protection bitmasks.
  /// Tracks recently received packet numbers to reject duplicates.
  final Map<PacketNumberSpace, int> _receivedWindow = {};

  PacketNumberSpaceManager() {
    for (final space in PacketNumberSpace.values) {
      _nextPacketNumber[space] = 0;
      _largestAcked[space] = -1;
      _largestReceived[space] = -1;
      _receivedWindow[space] = 0;
    }
  }

  /// Allocate the next packet number in a space.
  ///
  /// Returns the current next packet number and increments the internal
  /// counter so that the next call returns a value one greater.
  int allocate(PacketNumberSpace space) {
    final pn = _nextPacketNumber[space]!;
    _nextPacketNumber[space] = pn + 1;
    return pn;
  }

  /// Get the next packet number without allocating.
  ///
  /// Returns the value that would be returned by the next call to
  /// [allocate], but does not consume it.
  int peek(PacketNumberSpace space) {
    return _nextPacketNumber[space]!;
  }

  /// Record an ACKed packet number.
  ///
  /// Updates [largestAcked] for the given space if [packetNumber] is
  /// larger than the current largest acknowledged value.
  void onAck(PacketNumberSpace space, int packetNumber) {
    if (packetNumber > _largestAcked[space]!) {
      _largestAcked[space] = packetNumber;
    }
  }

  /// Record a received packet number.
  ///
  /// Updates [largestReceived] for the given space if [packetNumber]
  /// is larger than the current largest received value.
  ///
  /// SECURITY: Returns `false` if the packet number is a detected replay
  /// (already received within the replay window). Callers should drop
  /// replayed packets.
  bool onReceived(PacketNumberSpace space, int packetNumber) {
    // SECURITY: Reject negative packet numbers.
    if (packetNumber < 0) return false;

    final largest = _largestReceived[space]!;

    // Packet is newer than anything seen: advance window and accept.
    if (packetNumber > largest) {
      final diff = packetNumber - largest;
      if (diff >= _replayWindowSize) {
        _receivedWindow[space] = 0;
      } else {
        _receivedWindow[space] =
            (_receivedWindow[space]! << diff) & ((_replayWindowSize << 1) - 1);
      }
      _receivedWindow[space] = _receivedWindow[space]! | 1;
      _largestReceived[space] = packetNumber;
      return true;
    }

    // Packet is within the replay window: check bitmask.
    final diff = largest - packetNumber;
    if (diff >= _replayWindowSize) {
      return false; // Too old, outside window → replay.
    }
    final mask = 1 << diff;
    if ((_receivedWindow[space]! & mask) != 0) {
      return false; // Already seen → replay.
    }
    _receivedWindow[space] = _receivedWindow[space]! | mask;
    return true;
  }

  /// Get largest acked in a space.
  ///
  /// Returns -1 if no packet has been acknowledged in the space yet.
  int largestAcked(PacketNumberSpace space) {
    return _largestAcked[space]!;
  }

  /// Get largest received in a space.
  ///
  /// Returns -1 if no packet has been received in the space yet.
  int largestReceived(PacketNumberSpace space) {
    return _largestReceived[space]!;
  }

  /// Reset a single space to its initial state.
  ///
  /// The next packet number is set back to 0, and both largest acked
  /// and largest received are set to -1.
  void reset(PacketNumberSpace space) {
    _nextPacketNumber[space] = 0;
    _largestAcked[space] = -1;
    _largestReceived[space] = -1;
    _receivedWindow[space] = 0;
  }

  /// Reset all spaces to their initial state.
  void resetAll() {
    for (final space in PacketNumberSpace.values) {
      reset(space);
    }
  }
}

/// Packet number reconstruction for truncated short-header PNs.
///
/// Implements RFC 9000 Section 17.1.
library;

/// Reconstructs the full packet number from a truncated value.
///
/// [truncated] is the truncated packet number read from the wire.
/// [truncatedBits] is the number of bits used for the truncated value
/// (e.g. 8 for 1 byte, 16 for 2 bytes, 24 for 3 bytes, 32 for 4 bytes).
/// [largestReceived] is the highest received packet number in this space.
int reconstruct(int truncated, int truncatedBits, int largestReceived) {
  final window = 1 << truncatedBits;
  final expected = largestReceived + 1;
  final mask = window - 1;
  final candidate = (expected & ~mask) | truncated;

  // Find the candidate closest to expected among candidate ± window.
  var best = candidate;
  var bestDiff = (candidate - expected).abs();

  for (final c in [candidate - window, candidate + window]) {
    final diff = (c - expected).abs();
    if (diff < bestDiff) {
      best = c;
      bestDiff = diff;
    }
  }

  return best;
}

/// Truncates a full packet number to the lower [numBytes] bytes.
///
/// [numBytes] must be between 1 and 4 inclusive.
int truncate(int packetNumber, int numBytes) {
  if (numBytes < 1 || numBytes > 4) {
    throw ArgumentError('numBytes must be between 1 and 4, was $numBytes');
  }
  final bits = numBytes * 8;
  return packetNumber & ((1 << bits) - 1);
}

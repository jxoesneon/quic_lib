/// A libp2p PeerId represented as the raw multihash bytes of a public key.
///
/// Per the libp2p spec, a PeerId is the multihash of a public key. For now
/// base58/base36 encoding is not implemented; [toString] returns a hex
/// representation instead.
class PeerId {
  /// The raw multihash bytes (identity hash of the public key).
  final List<int> bytes;

  PeerId._(this.bytes);

  /// Create from a raw byte list.
  factory PeerId.fromBytes(List<int> bytes) {
    return PeerId._(List<int>.unmodifiable(List<int>.from(bytes)));
  }

  /// Create from a base58-encoded string.
  factory PeerId.fromBase58(String base58) {
    throw UnimplementedError('Base58 decoding is not yet implemented');
  }

  /// Convert to base58 string.
  String toBase58() {
    throw UnimplementedError('Base58 encoding is not yet implemented');
  }

  /// Convert to base36 string.
  String toBase36() {
    throw UnimplementedError('Base36 encoding is not yet implemented');
  }

  /// Returns a lowercase hex string representation of the bytes.
  @override
  String toString() {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! PeerId) return false;
    if (bytes.length != other.bytes.length) return false;
    for (var i = 0; i < bytes.length; i++) {
      if (bytes[i] != other.bytes[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode {
    // FNV-1a 32-bit inspired hash for byte lists.
    var hash = 0x811c9dc5;
    for (final b in bytes) {
      hash ^= b & 0xff;
      hash *= 0x01000193;
      hash &= 0xffffffff;
    }
    return hash;
  }
}

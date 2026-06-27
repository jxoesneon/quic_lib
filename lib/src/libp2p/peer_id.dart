/// A libp2p PeerId represented as the raw multihash bytes of a public key.
///
/// Per the libp2p spec, a PeerId is the multihash of a public key.
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
    return decodeBase58(base58);
  }

  /// Convert to base58 string.
  String toBase58() {
    return encodeBase58();
  }

  /// Convert to base36 string.
  String toBase36() {
    return encodeBase36();
  }

  /// Encodes this PeerId's raw bytes using standard Base58 (no multibase prefix).
  ///
  /// This is a scaffold implementation using the standard Bitcoin/Base58
  /// alphabet; it does not include the libp2p multibase prefix.
  String encodeBase58() {
    const alphabet =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    final data = List<int>.from(bytes);
    if (data.isEmpty) return '';

    var zeroCount = 0;
    while (zeroCount < data.length && data[zeroCount] == 0) {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (final b in data) {
      value = (value << 8) | BigInt.from(b);
    }

    final sb = StringBuffer();
    while (value > BigInt.zero) {
      final rem = value % BigInt.from(58);
      value = value ~/ BigInt.from(58);
      sb.write(alphabet[rem.toInt()]);
    }

    final encoded = sb.toString().split('').reversed.join();
    return '${'1' * zeroCount}$encoded';
  }

  /// Decodes a standard Base58-encoded string (no multibase prefix) into a [PeerId].
  ///
  /// This is a scaffold implementation using the standard Bitcoin/Base58
  /// alphabet; it does not handle the libp2p multibase prefix.
  static PeerId decodeBase58(String input) {
    const alphabet =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    final map = <String, int>{};
    for (var i = 0; i < alphabet.length; i++) {
      map[alphabet[i]] = i;
    }

    if (input.isEmpty) {
      return PeerId.fromBytes(<int>[]);
    }

    var zeroCount = 0;
    while (zeroCount < input.length && input[zeroCount] == '1') {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (var i = zeroCount; i < input.length; i++) {
      final char = input[i];
      final idx = map[char];
      if (idx == null) {
        throw ArgumentError('Invalid Base58 character: $char');
      }
      value = value * BigInt.from(58) + BigInt.from(idx);
    }

    final byteList = <int>[];
    while (value > BigInt.zero) {
      byteList.add((value & BigInt.from(0xFF)).toInt());
      value = value >> 8;
    }

    final reversed = byteList.reversed.toList();
    return PeerId.fromBytes(List<int>.filled(zeroCount, 0) + reversed);
  }

  /// Encodes this PeerId's raw bytes using standard Base36 (lowercase, no multibase prefix).
  ///
  /// This is a scaffold implementation using the standard Base36 alphabet;
  /// it does not include the libp2p multibase prefix.
  String encodeBase36() {
    const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    final data = List<int>.from(bytes);
    if (data.isEmpty) return '';

    var zeroCount = 0;
    while (zeroCount < data.length && data[zeroCount] == 0) {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (final b in data) {
      value = (value << 8) | BigInt.from(b);
    }

    final sb = StringBuffer();
    while (value > BigInt.zero) {
      final rem = value % BigInt.from(36);
      value = value ~/ BigInt.from(36);
      sb.write(alphabet[rem.toInt()]);
    }

    final encoded = sb.toString().split('').reversed.join();
    return '${'0' * zeroCount}$encoded';
  }

  /// Decodes a standard Base36-encoded string (lowercase, no multibase prefix) into a [PeerId].
  ///
  /// This is a scaffold implementation using the standard Base36 alphabet;
  /// it does not handle the libp2p multibase prefix.
  static PeerId decodeBase36(String input) {
    const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    final map = <String, int>{};
    for (var i = 0; i < alphabet.length; i++) {
      map[alphabet[i]] = i;
    }

    if (input.isEmpty) {
      return PeerId.fromBytes(<int>[]);
    }

    var zeroCount = 0;
    while (zeroCount < input.length && input[zeroCount] == '0') {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (var i = zeroCount; i < input.length; i++) {
      final char = input[i];
      final idx = map[char];
      if (idx == null) {
        throw ArgumentError('Invalid Base36 character: $char');
      }
      value = value * BigInt.from(36) + BigInt.from(idx);
    }

    final byteList = <int>[];
    while (value > BigInt.zero) {
      byteList.add((value & BigInt.from(0xFF)).toInt());
      value = value >> 8;
    }

    final reversed = byteList.reversed.toList();
    return PeerId.fromBytes(List<int>.filled(zeroCount, 0) + reversed);
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

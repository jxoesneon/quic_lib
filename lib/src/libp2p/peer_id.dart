/// A libp2p PeerId represented as the raw multihash bytes of a public key.
///
/// In the libp2p network stack, a [PeerId] uniquely identifies a peer.
/// It is conceptually the multihash of the peer's public key. This class
/// stores the raw byte representation and provides encoding/decoding to
/// common string formats used in libp2p: Base58 (default) and Base36.
///
/// [PeerId] values are immutable and can be compared for equality. The
/// [hashCode] implementation uses an FNV-1a 32-bit hash suitable for
/// collections such as [Map] and [Set].
///
/// ## Example
/// ```dart
/// final peerId = PeerId.fromBytes([0x12, 0x20, 0xab, 0xcd]);
/// final b58 = peerId.toBase58();
/// final recovered = PeerId.fromBase58(b58);
/// assert(peerId == recovered);
/// ```
///
/// See also:
/// - [Libp2pQuicTransport] — dials and listens using peer addressing.
/// - libp2p PeerId spec — https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
class PeerId {
  /// The raw multihash bytes (identity hash of the public key).
  ///
  /// This list is unmodifiable. Its length depends on the hash function
  /// and public key type used to generate the peer ID.
  final List<int> bytes;

  PeerId._(this.bytes);

  /// Creates a [PeerId] from a raw byte list.
  ///
  /// The returned instance stores an unmodifiable copy of [bytes].
  factory PeerId.fromBytes(List<int> bytes) {
    return PeerId._(List<int>.unmodifiable(List<int>.from(bytes)));
  }

  /// Creates a [PeerId] from a Base58-encoded string.
  ///
  /// Delegates to [decodeBase58]. Supports both plain Base58 and multibase
  /// strings prefixed with `z`.
  factory PeerId.fromBase58(String base58) {
    return decodeBase58(base58);
  }

  /// Returns the Base58 encoding of this peer ID.
  String toBase58() {
    return encodeBase58();
  }

  /// Returns the Base36 encoding of this peer ID.
  String toBase36() {
    return encodeBase36();
  }

  /// Encodes this PeerId's raw bytes using standard Base58 (Bitcoin alphabet).
  ///
  /// When [multibase] is true the result is prefixed with the multibase
  /// code `z` per the libp2p multibase specification. Leading zero bytes
  /// are encoded as `'1'` characters, matching the Bitcoin Base58 convention.
  ///
  /// Returns an empty string if [bytes] is empty.
  String encodeBase58({bool multibase = false}) {
    final prefix = multibase ? 'z' : '';
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
    return '$prefix${'1' * zeroCount}$encoded';
  }

  /// Decodes a Base58-encoded string into a [PeerId].
  ///
  /// If [input] starts with the multibase `z` prefix it is stripped before
  /// decoding. Leading `'1'` characters are decoded back to zero bytes.
  ///
  /// Throws [ArgumentError] if the string contains an invalid Base58 character.
  static PeerId decodeBase58(String input) {
    final stripped = input.startsWith('z') ? input.substring(1) : input;
    const alphabet =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    final map = <String, int>{};
    for (var i = 0; i < alphabet.length; i++) {
      map[alphabet[i]] = i;
    }

    if (stripped.isEmpty) {
      return PeerId.fromBytes(<int>[]);
    }

    var zeroCount = 0;
    while (zeroCount < stripped.length && stripped[zeroCount] == '1') {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (var i = zeroCount; i < stripped.length; i++) {
      final char = stripped[i];
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

  /// Encodes this PeerId's raw bytes using standard Base36 (lowercase).
  ///
  /// When [multibase] is true the result is prefixed with the multibase
  /// code `k` per the libp2p multibase specification. Leading zero bytes
  /// are encoded as `'0'` characters.
  ///
  /// Returns an empty string if [bytes] is empty.
  String encodeBase36({bool multibase = false}) {
    final prefix = multibase ? 'k' : '';
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
    return '$prefix${'0' * zeroCount}$encoded';
  }

  /// Decodes a Base36-encoded string into a [PeerId].
  ///
  /// If [input] starts with the multibase `k` prefix it is stripped before
  /// decoding. Leading `'0'` characters are decoded back to zero bytes.
  ///
  /// Throws [ArgumentError] if the string contains an invalid Base36 character.
  static PeerId decodeBase36(String input) {
    final stripped = input.startsWith('k') ? input.substring(1) : input;
    const alphabet = '0123456789abcdefghijklmnopqrstuvwxyz';
    final map = <String, int>{};
    for (var i = 0; i < alphabet.length; i++) {
      map[alphabet[i]] = i;
    }

    if (stripped.isEmpty) {
      return PeerId.fromBytes(<int>[]);
    }

    var zeroCount = 0;
    while (zeroCount < stripped.length && stripped[zeroCount] == '0') {
      zeroCount++;
    }

    var value = BigInt.zero;
    for (var i = zeroCount; i < stripped.length; i++) {
      final char = stripped[i];
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

  /// Returns a lowercase hex string representation of the raw bytes.
  ///
  /// Each byte is rendered as two hexadecimal digits (e.g. `0a1f2c`).
  /// For Base58 or Base36 representations use [toBase58] or [toBase36].
  @override
  String toString() {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  @override
  /// Whether two [PeerId]s represent the same raw byte sequence.
  ///
  /// Compares the lengths and contents of [bytes] element by element.
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
  /// A 32-bit hash code derived from the raw bytes using an FNV-1a algorithm.
  ///
  /// Suitable for use in [HashMap], [HashSet], and other Dart collections.
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

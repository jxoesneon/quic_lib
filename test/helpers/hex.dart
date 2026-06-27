/// Parses a hex string to a list of bytes.
///
/// Spaces are allowed and ignored. The string must contain an even number
/// of hex digits after whitespace removal.
///
/// Example:
/// ```dart
/// final bytes = hexDecode('c0 00 00'); // [0xc0, 0x00, 0x00]
/// ```
List<int> hexDecode(String hex) {
  final cleaned = hex.replaceAll(RegExp(r'\s+'), '');
  if (cleaned.length.isOdd) {
    throw FormatException('Hex string must have an even number of digits');
  }
  final bytes = <int>[];
  for (var i = 0; i < cleaned.length; i += 2) {
    final byte = int.tryParse(cleaned.substring(i, i + 2), radix: 16);
    if (byte == null) {
      throw FormatException('Invalid hex at position $i');
    }
    bytes.add(byte);
  }
  return bytes;
}

/// Converts a list of bytes to a lower-case hex string with spaces.
///
/// Example:
/// ```dart
/// final hex = hexEncode([0xc0, 0x00, 0x00]); // 'c0 00 00'
/// ```
String hexEncode(List<int> bytes) {
  return bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join(' ');
}

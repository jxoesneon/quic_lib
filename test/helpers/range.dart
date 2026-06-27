/// Compares two byte lists in a constant-time-ish manner.
///
/// Returns `true` iff both lists have the same length and every element
/// is identical. The loop always runs to the end of the shorter list
/// (or the full length when equal) to reduce timing leakage.
bool listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}

/// Concatenates multiple byte arrays into a single list.
List<int> concat(List<List<int>> parts) {
  final total = parts.fold<int>(0, (sum, p) => sum + p.length);
  final result = List<int>.filled(total, 0);
  var offset = 0;
  for (final part in parts) {
    for (var i = 0; i < part.length; i++) {
      result[offset + i] = part[i];
    }
    offset += part.length;
  }
  return result;
}

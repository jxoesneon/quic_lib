/// QUIC version constants and helpers per RFC 9000 and RFC 9369.
///
/// This class provides the canonical version identifiers used during
/// QUIC handshake and version negotiation. Callers should use [isSupported]
/// to determine whether a version received from a peer can be handled.
///
/// See also:
/// - [v1] — RFC 9000
/// - [v2] — RFC 9369
class QuicVersions {
  /// QUIC version 1 (RFC 9000).
  static const int v1 = 0x00000001;

  /// QUIC version 2 (RFC 9369).
  static const int v2 = 0x6b3343cf;

  /// Returns `true` if [version] is a supported QUIC version.
  ///
  /// Currently supports [v1] and [v2].
  static bool isSupported(int version) => version == v1 || version == v2;

  /// Returns a human-readable name for [version].
  ///
  /// Returns `'v1'` for [v1], `'v2'` for [v2], or `'unknown'` otherwise.
  static String name(int version) {
    if (version == v1) return 'v1';
    if (version == v2) return 'v2';
    return 'unknown';
  }
}

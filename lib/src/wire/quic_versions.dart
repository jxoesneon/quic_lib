/// QUIC version constants and helpers per RFC 9000 and RFC 9369.
class QuicVersions {
  /// QUIC version 1 (RFC 9000).
  static const int v1 = 0x00000001;

  /// QUIC version 2 (RFC 9369).
  static const int v2 = 0x6b3343cf;

  /// Returns `true` if [version] is a supported QUIC version.
  static bool isSupported(int version) => version == v1 || version == v2;

  /// Returns a human-readable name for [version].
  static String name(int version) {
    if (version == v1) return 'v1';
    if (version == v2) return 'v2';
    return 'unknown';
  }
}

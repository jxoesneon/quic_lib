import 'dart:typed_data';

/// RFC 9368 version_information transport parameter.
///
/// Wire format (from RFC 9368 Section 3):
/// ```
/// version_information {
///   chosen_version (32 bits),
///   available_versions (32 bits each),
///   other_versions (32 bits each)
/// }
/// ```
class VersionInformation {
  final int chosenVersion;
  final List<int> availableVersions;
  final List<int> otherVersions;

  VersionInformation({
    required this.chosenVersion,
    required this.availableVersions,
    this.otherVersions = const [],
  });

  /// Serialize to bytes.
  /// Format: chosen_version (4 bytes) + available_versions (4 bytes each) + other_versions (4 bytes each)
  Uint8List serialize() {
    final buffer = BytesBuilder();
    // chosen_version as 4-byte big-endian
    buffer.addByte((chosenVersion >> 24) & 0xFF);
    buffer.addByte((chosenVersion >> 16) & 0xFF);
    buffer.addByte((chosenVersion >> 8) & 0xFF);
    buffer.addByte(chosenVersion & 0xFF);
    // available_versions
    for (final v in availableVersions) {
      buffer.addByte((v >> 24) & 0xFF);
      buffer.addByte((v >> 16) & 0xFF);
      buffer.addByte((v >> 8) & 0xFF);
      buffer.addByte(v & 0xFF);
    }
    // other_versions (for greasing)
    for (final v in otherVersions) {
      buffer.addByte((v >> 24) & 0xFF);
      buffer.addByte((v >> 16) & 0xFF);
      buffer.addByte((v >> 8) & 0xFF);
      buffer.addByte(v & 0xFF);
    }
    return buffer.toBytes();
  }

  /// Parse from bytes.
  static VersionInformation parse(Uint8List bytes) {
    if (bytes.length < 4 || (bytes.length % 4) != 0) {
      throw FormatException(
          'version_information must be a multiple of 4 bytes');
    }
    final chosenVersion =
        (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    final versions = <int>[];
    for (var i = 4; i < bytes.length; i += 4) {
      versions.add((bytes[i] << 24) |
          (bytes[i + 1] << 16) |
          (bytes[i + 2] << 8) |
          bytes[i + 3]);
    }
    return VersionInformation(
      chosenVersion: chosenVersion,
      availableVersions: versions,
    );
  }

  /// Check if a version is compatible with the peer's available versions.
  bool isVersionCompatible(int version) => availableVersions.contains(version);

  /// Check if 0-RTT is compatible (client's chosen version must be in server's available versions).
  bool isZeroRttCompatible(VersionInformation serverInfo) {
    return serverInfo.availableVersions.contains(chosenVersion);
  }
}

import '../wire/packet_header.dart';
import '../wire/quic_versions.dart';

/// Constants and helpers for QUIC version negotiation.
class VersionNegotiation {
  /// The list of QUIC versions this implementation supports.
  static const List<int> supportedVersions = [
    QuicVersions.v1,
    QuicVersions.v2,
  ];

  /// Creates a [VersionNegotiationPacket] advertising the supported versions.
  static VersionNegotiationPacket createPacket({
    required List<int> destinationConnectionId,
    required List<int> sourceConnectionId,
  }) {
    return VersionNegotiationPacket(
      destinationConnectionId: destinationConnectionId,
      sourceConnectionId: sourceConnectionId,
      supportedVersions: supportedVersions,
    );
  }
}

import 'dart:typed_data';
import '../wire/packet_builder.dart';
import '../wire/packet_header.dart';
import '../wire/frame.dart';
import '../recovery/packet_number_space.dart';
import '../recovery/sent_packet_tracker.dart';

/// Builds and tracks outgoing QUIC packets.
class PacketSender {
  PacketSender._();

  static const int maxUdpPayloadSize = 1200;

  /// Build a packet for a given space.
  static Uint8List buildPacket({
    required List<Frame> frames,
    required PacketNumberSpace space,
    required List<int> dcid,
    List<int>? scid,
    required int packetNumber,
  }) {
    PacketHeader header;
    switch (space) {
      case PacketNumberSpace.initial:
        header = LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: dcid,
          sourceConnectionId: scid ?? [],
          packetNumber: packetNumber,
          token: const [],
        );
      case PacketNumberSpace.handshake:
        header = LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeHandshake,
          destinationConnectionId: dcid,
          sourceConnectionId: scid ?? [],
          packetNumber: packetNumber,
        );
      case PacketNumberSpace.application:
        header = ShortHeader(
          destinationConnectionId: dcid,
          packetNumber: packetNumber,
          packetNumberLength: 1,
        );
    }
    return PacketBuilder.build(header, frames);
  }

  /// Track a sent packet.
  static void trackSentPacket(SentPacketTracker tracker, SentPacketInfo info) {
    tracker.track(info);
  }

  /// Check if a packet should be sent for a space.
  static bool shouldSendPacket(PacketNumberSpace space, List<Frame> frames) {
    return frames.isNotEmpty;
  }
}

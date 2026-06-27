import 'dart:typed_data';
import '../wire/packet_header.dart';
import '../wire/quic_versions.dart';
import '../wire/coalesced_packet.dart';
import '../wire/frame.dart';
import '../recovery/packet_number_space.dart';

/// Processes incoming QUIC packets from raw UDP datagrams.
class PacketReceiver {
  PacketReceiver._();

  // SECURITY: Max frames per packet to prevent DoS via tiny frames.
  static const int maxFramesPerPacket = 256;

  /// Process a raw UDP datagram, splitting coalesced packets if needed.
  static List<({PacketHeader header, List<Frame> frames, PacketNumberSpace? space})> processDatagram(Uint8List datagram) {
    final packets = CoalescedPacket.split(datagram);
    final results = <({PacketHeader header, List<Frame> frames, PacketNumberSpace? space})>[];
    for (final packet in packets) {
      final result = processPacket(packet);
      if (result != null) {
        results.add(result);
      }
    }
    return results;
  }

  /// Process a single QUIC packet.
  /// Returns null if the packet is a Retry or Version Negotiation (special handling needed).
  static ({PacketHeader header, List<Frame> frames, PacketNumberSpace? space})? processPacket(Uint8List packet) {
    final header = PacketHeaderParser.parse(packet, destinationConnectionIdLength: _detectDcidLength(packet));
    final space = spaceFromHeader(header);

    if (space == null) {
      return null; // Retry or Version Negotiation
    }

    // Version check: allow QUIC v1 and v2. Unsupported versions are dropped
    // (in a full implementation this would trigger version negotiation).
    if (header is LongHeader) {
      if (!QuicVersions.isSupported(header.version)) {
        return null;
      }
    }

    // For now, assume the rest of the packet is frame payload
    // In a full implementation, header protection would be removed first,
    // then the payload decrypted, then frames parsed.
    final headerBytes = _headerLength(header);
    final payload = packet.sublist(headerBytes);

    final frames = <Frame>[];
    var offset = 0;
    while (offset < payload.length) {
      // SECURITY: Reject packets with excessive frame count.
      if (frames.length >= maxFramesPerPacket) {
        break;
      }
      try {
        final (frame, newOffset) = FrameCodec.parse(payload, offset: offset);
        frames.add(frame);
        offset = newOffset;
      } catch (_) {
        // SECURITY: If any frame is malformed, discard ALL frames from this
        // packet. QUIC requires the entire packet to be valid; partial
        // processing could allow frame-injection attacks.
        frames.clear();
        break;
      }
    }

    return (header: header, frames: frames, space: space);
  }

  /// Determine the packet number space from a header.
  static PacketNumberSpace? spaceFromHeader(PacketHeader header) {
    if (header is LongHeader) {
      switch (header.packetType) {
        case LongHeader.typeInitial:
          return PacketNumberSpace.initial;
        case LongHeader.typeHandshake:
          return PacketNumberSpace.handshake;
        case LongHeader.typeZeroRtt:
          return PacketNumberSpace.application;
        case LongHeader.typeRetry:
          return null;
        default:
          return null;
      }
    } else if (header is ShortHeader) {
      return PacketNumberSpace.application;
    }
    return null;
  }

  static int _detectDcidLength(Uint8List packet) {
    if (packet.isEmpty) return 0;
    final isLong = (packet[0] & 0x80) != 0;
    if (isLong && packet.length > 5) {
      return packet[5]; // DCID length byte in long header
    }
    return 8; // Default for short header
  }

  static int _headerLength(PacketHeader header) {
    if (header is LongHeader) {
      // Version (4) + DCID len (1) + DCID + SCID len (1) + SCID
      var len = 6 + header.destinationConnectionId.length + header.sourceConnectionId.length;
      if (header.isInitial) {
        // Token length + token (simplified: assume no token for now)
      }
      // Length varint + packet number (simplified)
      return len + 4;
    } else if (header is ShortHeader) {
      return 1 + header.destinationConnectionId.length + header.packetNumberLength;
    }
    return 0;
  }
}

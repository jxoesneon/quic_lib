import 'dart:typed_data';

/// Splits UDP datagrams that may contain multiple QUIC coalesced packets.
class CoalescedPacket {
  CoalescedPacket._();

  /// Check if a datagram likely contains coalesced packets.
  ///
  /// A datagram is coalesced if:
  /// - It contains a long header packet AND there are bytes remaining after it
  /// - Or it contains multiple long header packets
  static bool isCoalesced(Uint8List datagram) {
    if (datagram.isEmpty) return false;
    final packets = split(datagram);
    return packets.length > 1;
  }

  /// Split a UDP datagram into individual QUIC packets.
  ///
  /// Long header packets are split using their Length field.
  /// Short header packets consume the remainder of the datagram.
  static List<Uint8List> split(Uint8List datagram) {
    final result = <Uint8List>[];
    var offset = 0;

    while (offset < datagram.length) {
      final firstByte = datagram[offset];
      final isLong = (firstByte & 0x80) != 0;

      if (!isLong) {
        // Short header: remainder is a single packet
        result.add(datagram.sublist(offset));
        break;
      }

      // Long header: need to find the Length field
      final packetEnd = _findLongHeaderEnd(datagram, offset);
      if (packetEnd <= offset) {
        // Cannot parse further
        break;
      }
      result.add(datagram.sublist(offset, packetEnd));
      offset = packetEnd;
    }

    return result;
  }

  /// Find the end of a long-header packet starting at [offset].
  /// Returns the byte index after the packet, or [offset] if parsing fails.
  static int _findLongHeaderEnd(Uint8List bytes, int offset) {
    var pos = offset + 1; // skip first byte

    // Version (4 bytes)
    if (pos + 4 > bytes.length) return offset;
    pos += 4;

    // DCID length and value
    if (pos + 1 > bytes.length) return offset;
    final dcidLen = bytes[pos++];
    if (pos + dcidLen > bytes.length) return offset;
    pos += dcidLen;

    // SCID length and value
    if (pos + 1 > bytes.length) return offset;
    final scidLen = bytes[pos++];
    if (pos + scidLen > bytes.length) return offset;
    pos += scidLen;

    // For Initial: token length and token
    final packetType = (bytes[offset] >> 4) & 0x03;
    if (packetType == 0x00) {
      // Initial
      if (pos + 1 > bytes.length) return offset;
      final tokenLen = _decodeVarInt(bytes, pos);
      final tokenLenBytes = _varIntLength(bytes[pos]);
      pos += tokenLenBytes;
      if (pos + tokenLen > bytes.length) return offset;
      pos += tokenLen;
    }

    // Length field
    if (pos + 1 > bytes.length) return offset;
    final length = _decodeVarInt(bytes, pos);
    final lengthBytes = _varIntLength(bytes[pos]);
    pos += lengthBytes;

    // Payload
    if (pos + length > bytes.length) return offset;
    pos += length;

    return pos;
  }

  static int _decodeVarInt(Uint8List bytes, int offset) {
    // SECURITY: Guard against reading past buffer end.
    if (offset >= bytes.length) return 0;
    final firstByte = bytes[offset];
    final length = _varIntLength(firstByte);
    // SECURITY: Ensure all continuation bytes are present.
    if (offset + length > bytes.length) return 0;
    var value = firstByte & 0x3F;
    for (var i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  static int _varIntLength(int firstByte) {
    final flag = firstByte >> 6;
    return 1 << flag; // 1, 2, 4, or 8
  }
}

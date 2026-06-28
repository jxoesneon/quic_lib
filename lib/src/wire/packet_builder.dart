import 'dart:typed_data';
import 'frame.dart';
import 'packet_header.dart';
import 'packet_number.dart';

/// Builds complete QUIC packets from headers and frames.
class PacketBuilder {
  PacketBuilder._();

  /// Build a complete QUIC packet from a header and list of frames.
  ///
  /// For long headers, computes the Length field automatically.
  /// For short headers, appends frames directly after the header.
  static Uint8List build(PacketHeader header, List<Frame> frames) {
    final frameBytes = _serializeFrames(frames);

    if (header is LongHeader) {
      return _buildLongHeader(header, frameBytes);
    } else if (header is ShortHeader) {
      return _buildShortHeader(header, frameBytes);
    } else if (header is VersionNegotiationPacket) {
      return header.serialize();
    }

    throw UnsupportedError('Unsupported header type: ${header.runtimeType}');
  }

  static Uint8List _buildLongHeader(LongHeader header, Uint8List frameBytes) {
    if (header.isRetry) {
      return header.serialize(); // Retry has no frames
    }

    // Determine packet number byte length
    final pnLen = _pnLenFromValue(header.packetNumber);

    // Build payload: PN + frames
    final payloadBuilder = BytesBuilder();
    payloadBuilder.add(PacketNumber.encode(header.packetNumber, pnLen));
    payloadBuilder.add(frameBytes);
    final payload = Uint8List.fromList(payloadBuilder.toBytes());

    // Build header with correct length
    final headerBuilder = BytesBuilder();
    headerBuilder.addByte(0x80 | 0x40 | (header.packetType << 4));
    headerBuilder.addByte((header.version >> 24) & 0xFF);
    headerBuilder.addByte((header.version >> 16) & 0xFF);
    headerBuilder.addByte((header.version >> 8) & 0xFF);
    headerBuilder.addByte(header.version & 0xFF);
    headerBuilder.addByte(header.destinationConnectionId.length);
    headerBuilder.add(header.destinationConnectionId);
    headerBuilder.addByte(header.sourceConnectionId.length);
    headerBuilder.add(header.sourceConnectionId);

    if (header.isInitial) {
      final token = header.token ?? const <int>[];
      headerBuilder.add(_encodeVarInt(token.length));
      headerBuilder.add(token);
    }

    headerBuilder.add(_encodeVarInt(payload.length));
    headerBuilder.add(payload);

    return Uint8List.fromList(headerBuilder.toBytes());
  }

  static Uint8List _buildShortHeader(ShortHeader header, Uint8List frameBytes) {
    final builder = BytesBuilder();
    var firstByte = 0x40;
    if (header.spinBit) firstByte |= 0x20;
    firstByte |= (header.packetNumberLength - 1);
    if (header.keyPhase) firstByte |= 0x04;
    builder.addByte(firstByte);
    builder.add(header.destinationConnectionId);
    builder.add(
        PacketNumber.encode(header.packetNumber, header.packetNumberLength));
    builder.add(frameBytes);
    return Uint8List.fromList(builder.toBytes());
  }

  static Uint8List _serializeFrames(List<Frame> frames) {
    final builder = BytesBuilder();
    for (final frame in frames) {
      builder.add(frame.serialize());
    }
    return Uint8List.fromList(builder.toBytes());
  }

  static int _pnLenFromValue(int packetNumber) {
    if (packetNumber <= 0xFF) return 1;
    if (packetNumber <= 0xFFFF) return 2;
    if (packetNumber <= 0xFFFFFF) return 3;
    return 4;
  }

  static Uint8List _encodeVarInt(int value) {
    if (value <= 63) {
      return Uint8List(1)..[0] = value;
    } else if (value <= 16383) {
      return Uint8List(2)
        ..[0] = 0x40 | (value >> 8)
        ..[1] = value & 0xFF;
    } else if (value <= 1073741823) {
      return Uint8List(4)
        ..[0] = 0x80 | (value >> 24)
        ..[1] = (value >> 16) & 0xFF
        ..[2] = (value >> 8) & 0xFF
        ..[3] = value & 0xFF;
    } else {
      return Uint8List(8)
        ..[0] = 0xC0 | (value >> 56)
        ..[1] = (value >> 48) & 0xFF
        ..[2] = (value >> 40) & 0xFF
        ..[3] = (value >> 32) & 0xFF
        ..[4] = (value >> 24) & 0xFF
        ..[5] = (value >> 16) & 0xFF
        ..[6] = (value >> 8) & 0xFF
        ..[7] = value & 0xFF;
    }
  }
}

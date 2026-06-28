import 'dart:typed_data';

import 'packet_header.dart';
import 'quic_versions.dart';
import 'varint.dart';

/// QUIC v2 long header per RFC 9369.
///
/// This is a scaffold implementation. The real v2 header format needs the exact
/// bit layout per RFC 9369:
///   - v1 first byte: 1HF(1) | FixedBit(1) | LongPacketType(2) | TypeSpecific(4)
///   - v2 first byte: 1HF(1) | FixedBit(1) | Reserved(2) | TypeSpecific(2) | Version(2)
///
/// In v2 the packet type is encoded differently in the first byte (bits 3-2)
/// and the lower 2 bits of the version field are also carried in the first
/// byte (bits 1-0).
class V2LongHeader implements PacketHeader {
  static const int typeInitial = 0x00;
  static const int typeZeroRtt = 0x01;
  static const int typeHandshake = 0x02;
  static const int typeRetry = 0x03;

  final int version;
  final int packetType;
  @override final List<int> destinationConnectionId;
  final List<int> sourceConnectionId;
  final int packetNumber;
  final List<int> payload;
  final List<int>? token; // Only for Initial

  V2LongHeader({
    this.version = QuicVersions.v2,
    required this.packetType,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    this.packetNumber = 0,
    this.payload = const [],
    this.token,
  }) {
    if (packetType < 0 || packetType > 3) {
      throw ArgumentError('Invalid long packet type: $packetType');
    }
    if (destinationConnectionId.length > 255) {
      throw ArgumentError('DCID too long');
    }
    if (sourceConnectionId.length > 255) {
      throw ArgumentError('SCID too long');
    }
    if (packetType == typeInitial && token == null) {
      // token is optional even for Initial
    }
  }

  bool get isInitial => packetType == typeInitial;
  bool get isRetry => packetType == typeRetry;

  @override
  int get headerForm => 1;

  /// Builds the v2 first byte:
  ///   1 | 1 | 00 | PP | VV
  /// where PP = packet type (2 bits), VV = version (2 bits).
  int get _firstByte {
    // HF=1, FB=1, Reserved=00, PP=packetType<<2, VV=version&0x03
    return 0x80 | 0x40 | (packetType << 2) | (version & 0x03);
  }

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    // First byte: HF=1, FB=1, Reserved(2), TypeSpecific(2), Version(2)
    builder.addByte(_firstByte);
    // Version (4 bytes, big-endian)
    builder.addByte((version >> 24) & 0xFF);
    builder.addByte((version >> 16) & 0xFF);
    builder.addByte((version >> 8) & 0xFF);
    builder.addByte(version & 0xFF);
    // DCID length and value
    builder.addByte(destinationConnectionId.length);
    builder.add(destinationConnectionId);
    // SCID length and value
    builder.addByte(sourceConnectionId.length);
    builder.add(sourceConnectionId);

    if (isInitial) {
      // Token length (varint) and token
      final t = token ?? const <int>[];
      builder.add(VarInt.encode(t.length));
      builder.add(t);
    }

    if (!isRetry) {
      // Packet number + payload length as varint
      final pnBytes = _encodePacketNumber(packetNumber, _pnLengthFromValue(packetNumber));
      final length = pnBytes.length + payload.length;
      builder.add(VarInt.encode(length));
      builder.add(pnBytes);
      builder.add(payload);
    } else {
      // Retry: token + integrity tag (16 bytes placeholder)
      builder.add(payload); // payload serves as retry token
      builder.add(List<int>.filled(16, 0)); // placeholder integrity tag
    }

    return Uint8List.fromList(builder.toBytes());
  }

  @override
  int get byteLength {
    var len = 1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length;
    if (isInitial) {
      final t = token ?? const <int>[];
      len += VarInt.encode(t.length).length + t.length;
    }
    if (!isRetry) {
      final pnLen = _pnLengthFromValue(packetNumber);
      final lengthFieldLen = VarInt.encode(pnLen + payload.length).length;
      len += lengthFieldLen + pnLen + payload.length;
    } else {
      len += payload.length + 16;
    }
    return len;
  }

  /// Parse a [V2LongHeader] from serialized bytes.
  ///
  /// This is a scaffold parser for round-trip testing. It assumes the bytes
  /// were produced by [serialize] and does not perform full header-protection
  /// removal.
  static V2LongHeader parse(Uint8List bytes) {
    if (bytes.isEmpty) throw ArgumentError('Empty packet');
    final firstByte = bytes[0];
    if ((firstByte & 0x80) == 0) {
      throw ArgumentError('Not a long header');
    }

    var offset = 1;
    if (bytes.length < offset + 4) {
      throw ArgumentError('Packet too short for version');
    }
    final version = (bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3];
    offset += 4;

    if (version != QuicVersions.v2) {
      throw ArgumentError('Expected v2 version, got 0x${version.toRadixString(16)}');
    }

    final packetType = (firstByte >> 2) & 0x03;

    if (bytes.length < offset + 1) {
      throw ArgumentError('Packet too short for DCID length');
    }
    final dcidLen = bytes[offset++];
    if (bytes.length < offset + dcidLen) {
      throw ArgumentError('Packet too short for DCID');
    }
    final dcid = bytes.sublist(offset, offset + dcidLen);
    offset += dcidLen;

    if (bytes.length < offset + 1) {
      throw ArgumentError('Packet too short for SCID length');
    }
    final scidLen = bytes[offset++];
    if (bytes.length < offset + scidLen) {
      throw ArgumentError('Packet too short for SCID');
    }
    final scid = bytes.sublist(offset, offset + scidLen);
    offset += scidLen;

    List<int>? token;
    if (packetType == typeInitial) {
      if (bytes.length < offset + 1) {
        throw ArgumentError('Packet too short for token length');
      }
      final tokenLen = VarInt.decode(bytes.buffer, offset: offset);
      final tokenLenBytes = VarInt.decodeLength(bytes[offset]);
      offset += tokenLenBytes;
      if (bytes.length < offset + tokenLen) {
        throw ArgumentError('Packet too short for token');
      }
      token = bytes.sublist(offset, offset + tokenLen);
      offset += tokenLen;
    }

    if (packetType == typeRetry) {
      if (bytes.length < offset + 16) {
        throw ArgumentError('Packet too short for Retry');
      }
      final retryToken = bytes.sublist(offset, bytes.length - 16);
      return V2LongHeader(
        version: version,
        packetType: packetType,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        payload: retryToken,
      );
    }

    if (bytes.length < offset + 1) {
      throw ArgumentError('Packet too short for length');
    }
    final length = VarInt.decode(bytes.buffer, offset: offset);
    final lengthFieldBytes = VarInt.decodeLength(bytes[offset]);
    offset += lengthFieldBytes;
    if (bytes.length < offset + length) {
      throw ArgumentError('Packet too short for payload');
    }
    final payload = bytes.sublist(offset, offset + length);

    return V2LongHeader(
      version: version,
      packetType: packetType,
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
      packetNumber: 0,
      payload: payload,
      token: token,
    );
  }
}

/// Encode a packet number into the given byte length (1..4).
Uint8List _encodePacketNumber(int packetNumber, int byteLength) {
  final result = Uint8List(byteLength);
  for (var i = byteLength - 1; i >= 0; i--) {
    result[i] = packetNumber & 0xFF;
    packetNumber >>= 8;
  }
  return result;
}

/// Determine the minimum byte length needed to encode a packet number.
int _pnLengthFromValue(int packetNumber) {
  if (packetNumber <= 0xFF) return 1;
  if (packetNumber <= 0xFFFF) return 2;
  if (packetNumber <= 0xFFFFFF) return 3;
  return 4;
}

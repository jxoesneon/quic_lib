import 'dart:typed_data';
import 'varint.dart';

/// Base class for all QUIC packet headers.
abstract class PacketHeader {
  /// 1 for long header, 0 for short header.
  int get headerForm;

  /// The destination connection ID.
  List<int> get destinationConnectionId;

  /// Serialize this header to bytes.
  Uint8List serialize();

  /// Total serialized byte length.
  int get byteLength;
}

/// QUIC long header used during handshake (Initial, 0-RTT, Handshake, Retry).
class LongHeader implements PacketHeader {
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

  LongHeader({
    required this.version,
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

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    // First byte: HF=1, FB=1, LongPacketType(2), TypeSpecific(4)
    builder.addByte(0x80 | 0x40 | (packetType << 4));
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
}

/// QUIC short header used for 1-RTT application data.
class ShortHeader implements PacketHeader {
  @override final List<int> destinationConnectionId;
  final int packetNumber;
  final bool spinBit;
  final bool keyPhase;
  final int packetNumberLength; // 1..4
  final List<int> payload;

  ShortHeader({
    required this.destinationConnectionId,
    this.packetNumber = 0,
    this.spinBit = false,
    this.keyPhase = false,
    this.packetNumberLength = 1,
    this.payload = const [],
  }) {
    if (packetNumberLength < 1 || packetNumberLength > 4) {
      throw ArgumentError('PN length must be 1..4');
    }
    if (destinationConnectionId.length > 255) {
      throw ArgumentError('DCID too long');
    }
  }

  @override
  int get headerForm => 0;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    // First byte: HF=0, FB=1, SpinBit, Reserved(0), KeyPhase, PN Length - 1
    var firstByte = 0x40;
    if (spinBit) firstByte |= 0x20;
    firstByte |= (packetNumberLength - 1);
    if (keyPhase) firstByte |= 0x04;
    builder.addByte(firstByte);
    builder.add(destinationConnectionId);
    builder.add(_encodePacketNumber(packetNumber, packetNumberLength));
    builder.add(payload);
    return Uint8List.fromList(builder.toBytes());
  }

  @override
  int get byteLength => 1 + destinationConnectionId.length + packetNumberLength + payload.length;
}

/// Version negotiation packet sent when a peer doesn't support the requested version.
class VersionNegotiationPacket implements PacketHeader {
  @override final List<int> destinationConnectionId;
  final List<int> sourceConnectionId;
  final List<int> supportedVersions;

  VersionNegotiationPacket({
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    required this.supportedVersions,
  }) {
    if (destinationConnectionId.length > 255 || sourceConnectionId.length > 255) {
      throw ArgumentError('CID too long');
    }
  }

  @override
  int get headerForm => 1;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x80 | 0x40); // Long header, version negotiation type bits
    builder.addByte(0);
    builder.addByte(0);
    builder.addByte(0);
    builder.addByte(0); // Version = 0x00000000
    builder.addByte(destinationConnectionId.length);
    builder.add(destinationConnectionId);
    builder.addByte(sourceConnectionId.length);
    builder.add(sourceConnectionId);
    for (final v in supportedVersions) {
      builder.addByte((v >> 24) & 0xFF);
      builder.addByte((v >> 16) & 0xFF);
      builder.addByte((v >> 8) & 0xFF);
      builder.addByte(v & 0xFF);
    }
    return Uint8List.fromList(builder.toBytes());
  }

  @override
  int get byteLength =>
      1 + 4 + 1 + destinationConnectionId.length + 1 + sourceConnectionId.length + supportedVersions.length * 4;
}

/// Parses QUIC packet headers from raw bytes.
class PacketHeaderParser {
  static PacketHeader parse(Uint8List bytes, {required int destinationConnectionIdLength}) {
    if (bytes.isEmpty) throw ArgumentError('Empty packet');
    final firstByte = bytes[0];
    final isLong = (firstByte & 0x80) != 0;
    if (isLong) {
      return _parseLongHeader(bytes);
    } else {
      return _parseShortHeader(bytes, destinationConnectionIdLength);
    }
  }

  static PacketHeader _parseLongHeader(Uint8List bytes) {
    var offset = 1; // skip first byte
    if (bytes.length < offset + 4) throw ArgumentError('Packet too short for version');
    final version = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;

    if (version == 0) {
      // Version negotiation
      if (bytes.length < offset + 1) throw ArgumentError('Packet too short for DCID length');
      final dcidLen = bytes[offset++];
      if (bytes.length < offset + dcidLen) throw ArgumentError('Packet too short for DCID');
      final dcid = bytes.sublist(offset, offset + dcidLen);
      offset += dcidLen;
      if (bytes.length < offset + 1) throw ArgumentError('Packet too short for SCID length');
      final scidLen = bytes[offset++];
      if (bytes.length < offset + scidLen) throw ArgumentError('Packet too short for SCID');
      final scid = bytes.sublist(offset, offset + scidLen);
      offset += scidLen;
      final versions = <int>[];
      while (offset + 4 <= bytes.length) {
        final v = (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
        versions.add(v);
        offset += 4;
      }
      return VersionNegotiationPacket(
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        supportedVersions: versions,
      );
    }

    final packetType = (bytes[0] >> 4) & 0x03;
    if (bytes.length < offset + 1) throw ArgumentError('Packet too short for DCID length');
    final dcidLen = bytes[offset++];
    if (bytes.length < offset + dcidLen) throw ArgumentError('Packet too short for DCID');
    final dcid = bytes.sublist(offset, offset + dcidLen);
    offset += dcidLen;
    if (bytes.length < offset + 1) throw ArgumentError('Packet too short for SCID length');
    final scidLen = bytes[offset++];
    if (bytes.length < offset + scidLen) throw ArgumentError('Packet too short for SCID');
    final scid = bytes.sublist(offset, offset + scidLen);
    offset += scidLen;

    List<int>? token;
    if (packetType == LongHeader.typeInitial) {
      if (bytes.length < offset + 1) throw ArgumentError('Packet too short for token length');
      final tokenLen = VarInt.decode(bytes.buffer, offset: offset);
      final tokenLenBytes = VarInt.decodeLength(bytes[offset]);
      offset += tokenLenBytes;
      if (bytes.length < offset + tokenLen) throw ArgumentError('Packet too short for token');
      token = bytes.sublist(offset, offset + tokenLen);
      offset += tokenLen;
    }

    if (packetType == LongHeader.typeRetry) {
      // Retry token is the remainder minus 16 bytes for integrity tag
      if (bytes.length < offset + 16) throw ArgumentError('Packet too short for Retry');
      final retryToken = bytes.sublist(offset, bytes.length - 16);
      return LongHeader(
        version: version,
        packetType: packetType,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        payload: retryToken,
      );
    }

    if (bytes.length < offset + 1) throw ArgumentError('Packet too short for length');
    final length = VarInt.decode(bytes.buffer, offset: offset);
    final lengthFieldBytes = VarInt.decodeLength(bytes[offset]);
    offset += lengthFieldBytes;
    if (bytes.length < offset + length) throw ArgumentError('Packet too short for payload');
    final payload = bytes.sublist(offset, offset + length);

    // Packet number extraction is deferred to the caller because the exact
    // packet number length depends on header protection removal.
    return LongHeader(
      version: version,
      packetType: packetType,
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
      packetNumber: 0,
      payload: payload,
      token: token,
    );
  }

  static PacketHeader _parseShortHeader(Uint8List bytes, int dcidLen) {
    var offset = 1;
    if (bytes.length < offset + dcidLen) throw ArgumentError('Packet too short for DCID');
    final dcid = bytes.sublist(offset, offset + dcidLen);
    offset += dcidLen;
    final firstByte = bytes[0];
    final pnLen = (firstByte & 0x03) + 1;
    if (bytes.length < offset + pnLen) throw ArgumentError('Packet too short for PN');
    var pn = 0;
    for (var i = 0; i < pnLen; i++) {
      pn = (pn << 8) | bytes[offset + i];
    }
    offset += pnLen;
    final payload = bytes.sublist(offset);
    return ShortHeader(
      destinationConnectionId: dcid,
      packetNumber: pn,
      spinBit: (firstByte & 0x20) != 0,
      keyPhase: (firstByte & 0x04) != 0,
      packetNumberLength: pnLen,
      payload: payload,
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

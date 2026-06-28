import 'dart:typed_data';

import '../crypto/crypto_backend.dart';
import '../crypto/packet/retry_integrity_tag.dart';
import 'packet_header.dart';
import 'quic_versions.dart';
import 'varint.dart';

/// QUIC v2 long header per RFC 9369.
///
/// v2 first byte layout:
///   1HF(1) | FixedBit(1) | Reserved(2) | TypeSpecific(2) | Version(2)
///
/// In v2 the packet type is encoded in bits 3-2 of the first byte and the
/// lower 2 bits of the version field are carried in bits 1-0.
///
/// This header is used for the same packet types as [LongHeader] but with
/// the incompatible bit layout required by QUIC v2.
///
/// See also:
/// - [LongHeader] — QUIC v1 long header
/// - [QuicVersions.v2] — version constant
/// - RFC 9369
class V2LongHeader implements PacketHeader {
  /// Packet type constant for Initial packets.
  static const int typeInitial = 0x00;

  /// Packet type constant for 0-RTT packets.
  static const int typeZeroRtt = 0x01;

  /// Packet type constant for Handshake packets.
  static const int typeHandshake = 0x02;

  /// Packet type constant for Retry packets.
  static const int typeRetry = 0x03;

  /// The QUIC version, typically [QuicVersions.v2].
  final int version;

  /// The long packet type (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry).
  final int packetType;

  /// The destination connection ID.
  @override
  final List<int> destinationConnectionId;

  /// The source connection ID.
  final List<int> sourceConnectionId;

  /// The packet number (truncated on the wire).
  final int packetNumber;

  /// The payload bytes (frames for non-Retry, retry token for Retry).
  final List<int> payload;

  /// The address-validation token (Initial packets only).
  final List<int>? token;

  /// Cryptographic backend required for Retry integrity tag computation.
  final CryptoBackend? backend;

  /// Creates a v2 long header.
  ///
  /// [packetType] must be one of [typeInitial], [typeZeroRtt],
  /// [typeHandshake], or [typeRetry].
  /// [destinationConnectionId] and [sourceConnectionId] must each be
  /// 255 bytes or fewer.
  /// [backend] is required when serializing Retry packets.
  ///
  /// Throws [ArgumentError] if packet type or CID lengths are invalid.
  V2LongHeader({
    this.version = QuicVersions.v2,
    required this.packetType,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    this.packetNumber = 0,
    this.payload = const [],
    this.token,
    this.backend,
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

  /// Whether this is an Initial packet.
  bool get isInitial => packetType == typeInitial;

  /// Whether this is a Retry packet.
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
  Future<Uint8List> serialize() async {
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
      final pnBytes =
          _encodePacketNumber(packetNumber, _pnLengthFromValue(packetNumber));
      final length = pnBytes.length + payload.length;
      builder.add(VarInt.encode(length));
      builder.add(pnBytes);
      builder.add(payload);
    } else {
      // Retry: token + integrity tag
      builder.add(payload); // payload serves as retry token
      if (backend == null) {
        throw StateError('backend is required to serialize Retry packets');
      }
      final retryPacketWithoutTag = Uint8List.fromList(builder.toBytes());
      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: destinationConnectionId,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend!,
      );
      builder.add(tag);
    }

    return Uint8List.fromList(builder.toBytes());
  }

  @override
  int get byteLength {
    var len = 1 +
        4 +
        1 +
        destinationConnectionId.length +
        1 +
        sourceConnectionId.length;
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
  /// Parses the full v2 long header structure per RFC 9369.
  /// Header protection must be removed before calling this method.
  ///
  /// Throws [ArgumentError] if the bytes do not represent a valid v2 packet.
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
      throw ArgumentError(
          'Expected v2 version, got 0x${version.toRadixString(16)}');
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

Uint8List _encodePacketNumber(int packetNumber, int byteLength) {
  final result = Uint8List(byteLength);
  for (var i = byteLength - 1; i >= 0; i--) {
    result[i] = packetNumber & 0xFF;
    packetNumber >>= 8;
  }
  return result;
}

int _pnLengthFromValue(int packetNumber) {
  if (packetNumber <= 0xFF) return 1;
  if (packetNumber <= 0xFFFF) return 2;
  if (packetNumber <= 0xFFFFFF) return 3;
  return 4;
}

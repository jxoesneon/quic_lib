import 'dart:typed_data';

import '../crypto/crypto_backend.dart';
import '../crypto/packet/retry_integrity_tag.dart';
import 'quic_bit_greaser.dart';
import 'varint.dart';

/// Base class for all QUIC packet headers.
///
/// QUIC defines two header forms: long (header form = 1) used during the
/// handshake, and short (header form = 0) used for 1-RTT data. All
/// concrete implementations ([LongHeader], [ShortHeader],
/// [VersionNegotiationPacket]) expose the same basic properties and can be
/// serialized to bytes via [serialize].
///
/// See also:
/// - [LongHeader] — handshake-time long header
/// - [ShortHeader] — 1-RTT short header
/// - [PacketHeaderParser] — for parsing raw bytes into headers
/// - RFC 9000 Section 17
abstract class PacketHeader {
  /// The header form: 1 for long header, 0 for short header.
  int get headerForm;

  /// The destination connection ID.
  ///
  /// This CID is used by the receiver to route the packet to the correct
  /// connection context.
  List<int> get destinationConnectionId;

  /// Serialize this header to bytes.
  ///
  /// For [LongHeader] Retry packets, this is an async operation because it
  /// computes the integrity tag.
  Future<Uint8List> serialize();

  /// Total serialized byte length.
  ///
  /// This is the on-the-wire size before encryption and UDP overhead.
  int get byteLength;
}

/// QUIC long header used during handshake (Initial, 0-RTT, Handshake, Retry).
///
/// The long header carries the version, both connection IDs, and a Length
/// field that prefixes the protected payload. Initial packets may also
/// carry an address-validation token.
///
/// See also:
/// - [ShortHeader] — used after the handshake
/// - [VersionNegotiationPacket] — sent when versions mismatch
/// - [RetryPacketBuilder] — builds Retry packets specifically
/// - RFC 9000 Section 17.2
class LongHeader implements PacketHeader {
  /// Packet type constant for Initial packets.
  static const int typeInitial = 0x00;

  /// Packet type constant for 0-RTT packets.
  static const int typeZeroRtt = 0x01;

  /// Packet type constant for Handshake packets.
  static const int typeHandshake = 0x02;

  /// Packet type constant for Retry packets.
  static const int typeRetry = 0x03;

  /// The QUIC version (e.g., [QuicVersions.v1]).
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

  /// The address-validation token (Initial packets only, optional).
  final List<int>? token;

  /// Cryptographic backend required for Retry integrity tag computation.
  final CryptoBackend? backend;

  /// Creates a long header.
  ///
  /// [packetType] must be one of [typeInitial], [typeZeroRtt],
  /// [typeHandshake], or [typeRetry].
  /// [destinationConnectionId] and [sourceConnectionId] must each be
  /// 255 bytes or fewer.
  /// [backend] is required when serializing Retry packets.
  ///
  /// Throws [ArgumentError] if packet type or CID lengths are invalid.
  LongHeader({
    required this.version,
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

  @override
  Future<Uint8List> serialize() async {
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
}

/// QUIC short header used for 1-RTT application data.
///
/// The short header omits the version and source connection ID, keeping only
/// the destination connection ID and a truncated packet number. It also
/// carries the spin bit (latency measurement) and key-phase bit (key update).
///
/// See also:
/// - [LongHeader] — used during the handshake
/// - [PacketBuilder] — assembles packets with short headers
/// - RFC 9000 Section 17.3
class ShortHeader implements PacketHeader {
  /// The destination connection ID.
  @override
  final List<int> destinationConnectionId;

  /// The packet number (truncated to [packetNumberLength] bytes on wire).
  final int packetNumber;

  /// The spin bit used for latency measurement (RFC 9000 Section 17.3.1).
  final bool spinBit;

  /// The key phase bit indicating which packet-protection keys are in use.
  final bool keyPhase;

  /// The byte length of the truncated packet number on the wire (1..4).
  final int packetNumberLength;

  /// The payload bytes (frames) carried after the header.
  final List<int> payload;

  /// Whether to randomly set or clear the QUIC bit (RFC 9287).
  final bool greaseQuicBit;

  /// Creates a short header.
  ///
  /// [destinationConnectionId] must be 255 bytes or fewer.
  /// [packetNumberLength] must be between 1 and 4 inclusive.
  ///
  /// Throws [ArgumentError] if any constraint is violated.
  ShortHeader({
    required this.destinationConnectionId,
    this.packetNumber = 0,
    this.spinBit = false,
    this.keyPhase = false,
    this.packetNumberLength = 1,
    this.payload = const [],
    this.greaseQuicBit = false,
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
  Future<Uint8List> serialize() async {
    final builder = BytesBuilder();
    // First byte: HF=0, FB=1, SpinBit, Reserved(0), KeyPhase, PN Length - 1
    var firstByte = 0x40;
    if (greaseQuicBit && !QuicBitGreaser.shouldGrease()) {
      firstByte &= ~0x40;
    }
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
  int get byteLength =>
      1 + destinationConnectionId.length + packetNumberLength + payload.length;
}

/// Version negotiation packet sent when a peer doesn't support the requested version.
///
/// When a server receives an Initial packet with an unknown version, it
/// replies with a Version Negotiation packet containing a list of supported
/// versions. This packet has version 0x00000000 and no packet number.
///
/// See also:
/// - [LongHeader] — the header format from which this diverges
/// - [QuicVersions] — supported version constants
/// - RFC 9000 Section 17.2.1
class VersionNegotiationPacket implements PacketHeader {
  /// The destination connection ID (copied from the incoming Initial).
  @override
  final List<int> destinationConnectionId;

  /// The source connection ID chosen by the server.
  final List<int> sourceConnectionId;

  /// The list of versions this endpoint supports.
  final List<int> supportedVersions;

  /// Creates a version negotiation packet.
  ///
  /// [destinationConnectionId] and [sourceConnectionId] must each be
  /// 255 bytes or fewer.
  ///
  /// Throws [ArgumentError] if any CID exceeds the limit.
  VersionNegotiationPacket({
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    required this.supportedVersions,
  }) {
    if (destinationConnectionId.length > 255 ||
        sourceConnectionId.length > 255) {
      throw ArgumentError('CID too long');
    }
  }

  @override
  int get headerForm => 1;

  @override
  Future<Uint8List> serialize() async {
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
      1 +
      4 +
      1 +
      destinationConnectionId.length +
      1 +
      sourceConnectionId.length +
      supportedVersions.length * 4;
}

/// Parses QUIC packet headers from raw bytes.
///
/// [PacketHeaderParser.parse] inspects the first byte to determine whether
/// the packet uses a long or short header, then dispatches to the appropriate
/// parser. For short headers, the caller must supply the expected DCID length
/// because it is not encoded in the packet itself.
///
/// ## Example
/// ```dart
/// final header = PacketHeaderParser.parse(
///   datagram,
///   destinationConnectionIdLength: 8,
/// );
/// ```
///
/// See also:
/// - [PacketHeader] — base class for parsed headers
/// - [LongHeader] — parsed long header type
/// - [ShortHeader] — parsed short header type
class PacketHeaderParser {
  /// Parse a [PacketHeader] from raw [bytes].
  ///
  /// [destinationConnectionIdLength] is required for short-header packets
  /// because the short header does not encode the DCID length.
  ///
  /// Returns a [LongHeader], [ShortHeader], or [VersionNegotiationPacket]
  /// depending on the first byte and version field.
  ///
  /// Throws [ArgumentError] if the buffer is empty or too short.
  static PacketHeader parse(Uint8List bytes,
      {required int destinationConnectionIdLength}) {
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
    if (bytes.length < offset + 4) {
      throw ArgumentError('Packet too short for version');
    }
    final version = (bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3];
    offset += 4;

    if (version == 0) {
      // Version negotiation
      if (bytes.length < offset + 1) {
        throw ArgumentError('Packet too short for DCID length');
      }
      final dcidLen = bytes[offset++];
      if (dcidLen > 20) throw ArgumentError('DCID too long (max 20 bytes)');
      if (bytes.length < offset + dcidLen) {
        throw ArgumentError('Packet too short for DCID');
      }
      final dcid = bytes.sublist(offset, offset + dcidLen);
      offset += dcidLen;
      if (bytes.length < offset + 1) {
        throw ArgumentError('Packet too short for SCID length');
      }
      final scidLen = bytes[offset++];
      if (scidLen > 20) throw ArgumentError('SCID too long (max 20 bytes)');
      if (bytes.length < offset + scidLen) {
        throw ArgumentError('Packet too short for SCID');
      }
      final scid = bytes.sublist(offset, offset + scidLen);
      offset += scidLen;
      final versions = <int>[];
      const maxVersions = 32;
      while (offset + 4 <= bytes.length && versions.length < maxVersions) {
        final v = (bytes[offset] << 24) |
            (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) |
            bytes[offset + 3];
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
    if (bytes.length < offset + 1) {
      throw ArgumentError('Packet too short for DCID length');
    }
    final dcidLen = bytes[offset++];
    if (dcidLen > 20) throw ArgumentError('DCID too long (max 20 bytes)');
    if (bytes.length < offset + dcidLen) {
      throw ArgumentError('Packet too short for DCID');
    }
    final dcid = bytes.sublist(offset, offset + dcidLen);
    offset += dcidLen;
    if (bytes.length < offset + 1) {
      throw ArgumentError('Packet too short for SCID length');
    }
    final scidLen = bytes[offset++];
    if (scidLen > 20) throw ArgumentError('SCID too long (max 20 bytes)');
    if (bytes.length < offset + scidLen) {
      throw ArgumentError('Packet too short for SCID');
    }
    final scid = bytes.sublist(offset, offset + scidLen);
    offset += scidLen;

    List<int>? token;
    if (packetType == LongHeader.typeInitial) {
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

    if (packetType == LongHeader.typeRetry) {
      // Retry token is the remainder minus 16 bytes for integrity tag
      if (bytes.length < offset + 16) {
        throw ArgumentError('Packet too short for Retry');
      }
      final retryToken = bytes.sublist(offset, bytes.length - 16);
      return LongHeader(
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
    if (bytes.length < offset + dcidLen) {
      throw ArgumentError('Packet too short for DCID');
    }
    final dcid = bytes.sublist(offset, offset + dcidLen);
    offset += dcidLen;
    final firstByte = bytes[0];
    final pnLen = (firstByte & 0x03) + 1;
    if (bytes.length < offset + pnLen) {
      throw ArgumentError('Packet too short for PN');
    }
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

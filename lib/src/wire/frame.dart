import 'dart:math';
import 'dart:typed_data';
import 'varint.dart';

/// Base class for all QUIC frames.
abstract class Frame {
  int get frameType;
  Uint8List serialize();

  /// Whether this frame is ack-eliciting per RFC 9000 Table 3.
  /// Default is `true`; override for non-ack-eliciting frames.
  bool get isAckEliciting => true;

  /// Whether this frame counts toward bytes in flight per RFC 9000 Table 3.
  /// Default matches [isAckEliciting]; override for frames that are not
  /// ack-eliciting but still should not count (e.g., CONNECTION_CLOSE).
  bool get isInFlight => isAckEliciting;
}

/// Identifiers for QUIC frame types (RFC 9000 Section 19 and extensions).
///
/// This enum is used for type-safe frame identification. Individual [Frame]
/// implementations also expose their type via the [frameType] getter.
enum FrameType {
  padding(0x00),
  ping(0x01),
  ack(0x02),
  ackEcn(0x03),
  resetStream(0x04),
  stopSending(0x05),
  crypto(0x06),
  newToken(0x07),
  stream(0x08),
  maxData(0x10),
  maxStreamData(0x11),
  maxStreams(0x12),
  dataBlocked(0x14),
  streamDataBlocked(0x15),
  streamsBlocked(0x16),
  newConnectionId(0x18),
  retireConnectionId(0x19),
  pathChallenge(0x1a),
  pathResponse(0x1b),
  connectionClose(0x1c),
  applicationClose(0x1d),
  handshakeDone(0x1e),
  datagram(0x30),
  datagramWithLength(0x31),
  /// ACK_FREQUENCY frame (RFC 9298).
  ///
  /// Allows a receiver to request the sender to change its acknowledgement
  /// frequency, reducing overhead on high-bandwidth or asymmetric paths.
  ackFrequency(0xaf);

  final int value;
  const FrameType(this.value);
}

// ---------------------------------------------------------------------------
// 0x00 PADDING
// ---------------------------------------------------------------------------
/// A PADDING frame (RFC 9000 Section 19.1).
class PaddingFrame extends Frame {
  final int length;
  PaddingFrame({this.length = 1});
  @override
  int get frameType => 0x00;
  @override
  Uint8List serialize() => Uint8List(length);
  @override
  bool get isAckEliciting => false;
  @override
  bool get isInFlight => false;
}

// ---------------------------------------------------------------------------
// 0x01 PING
// ---------------------------------------------------------------------------
/// A PING frame (RFC 9000 Section 19.2).
class PingFrame extends Frame {
  PingFrame();
  @override
  int get frameType => 0x01;
  @override
  Uint8List serialize() => Uint8List(1)..[0] = 0x01;
}

// ---------------------------------------------------------------------------
// 0x02 ACK
// ---------------------------------------------------------------------------
/// An ACK frame (RFC 9000 Section 19.3).
class AckFrame extends Frame {
  final int largestAcknowledged;
  final int ackDelay;
  final List<AckRange> ackRanges;

  AckFrame({
    required this.largestAcknowledged,
    this.ackDelay = 0,
    this.ackRanges = const [],
  });

  @override
  int get frameType => 0x02;
  @override
  bool get isAckEliciting => false;
  @override
  bool get isInFlight => false;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x02);
    builder.add(VarInt.encode(largestAcknowledged));
    builder.add(VarInt.encode(ackDelay));
    builder.add(VarInt.encode(ackRanges.length));
    if (ackRanges.isNotEmpty) {
      builder.add(VarInt.encode(ackRanges.first.length)); // First ACK Range
      for (final range in ackRanges.skip(1)) {
        builder.add(VarInt.encode(range.gap));
        builder.add(VarInt.encode(range.length));
      }
    } else {
      builder.add(VarInt.encode(0));
    }
    return Uint8List.fromList(builder.toBytes());
  }
}

/// A single range of contiguous packet numbers acknowledged in an ACK frame.
///
/// ACK frames in QUIC (RFC 9000 Section 19.3) encode acknowledgment information
/// compactly using a largest-acknowledged number plus a list of [AckRange]s.
/// Each range describes a gap from the previous range and a length of
/// contiguously acknowledged packets.
///
/// The first range in an [AckFrame] has a `gap` of zero and its `length`
/// counts backward from [AckFrame.largestAcknowledged].
///
/// See also:
/// - [AckFrame] — the frame that aggregates these ranges.
/// - [AckEcnFrame] — ECN-aware variant that also includes ACK ranges.
/// - RFC 9000 Section 19.3.1 — ACK range encoding.
class AckRange {
  /// The gap from the end of the previous ACK range to the start of this one.
  final int gap;

  /// The number of contiguously acknowledged packets in this range.
  final int length;

  /// Creates an [AckRange] with the given [gap] and [length].
  ///
  /// For the first range in an ACK frame, [gap] should be `0`.
  AckRange({this.gap = 0, required this.length});
}

// ---------------------------------------------------------------------------
// 0x03 ACK with ECN
// ---------------------------------------------------------------------------
/// An ACK frame with ECN (Explicit Congestion Notification) counts (RFC 9000 Section 19.3.2).
///
/// [AckEcnFrame] extends [AckFrame] by adding three ECN counters: [ect0Count],
/// [ect1Count], and [ceCount]. These values allow the sender to detect ECN-capable
/// path support and react to congestion experienced (CE) marks.
///
/// This frame type (0x03) is used instead of a plain ACK (0x02) when the peer
/// has negotiated ECN support and the received packets carried ECN-capable codepoints.
///
/// See also:
/// - [AckFrame] — the base ACK frame without ECN counts.
/// - [AckRange] — the packet-number ranges carried by this frame.
/// - RFC 9000 Section 19.3.2 — ACK frame with ECN counts.
class AckEcnFrame extends AckFrame {
  /// Count of IP packets received with the ECT(0) codepoint.
  final int ect0Count;

  /// Count of IP packets received with the ECT(1) codepoint.
  final int ect1Count;

  /// Count of IP packets received with the CE codepoint.
  final int ceCount;

  /// Creates an [AckEcnFrame] that acknowledges packets and reports ECN counts.
  ///
  /// All parameters are inherited from [AckFrame] except the ECN-specific
  /// [ect0Count], [ect1Count], and [ceCount].
  AckEcnFrame({
    required super.largestAcknowledged,
    super.ackDelay,
    super.ackRanges,
    this.ect0Count = 0,
    this.ect1Count = 0,
    this.ceCount = 0,
  });

  @override
  int get frameType => 0x03;

  @override
  Uint8List serialize() {
    final base = super.serialize();
    // Replace type byte
    base[0] = 0x03;
    final builder = BytesBuilder();
    builder.add(base);
    builder.add(VarInt.encode(ect0Count));
    builder.add(VarInt.encode(ect1Count));
    builder.add(VarInt.encode(ceCount));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x04 RESET_STREAM
// ---------------------------------------------------------------------------
/// A RESET_STREAM frame (RFC 9000 Section 19.4).
class ResetStreamFrame extends Frame {
  final int streamId;
  final int errorCode;
  final int finalSize;

  ResetStreamFrame(
      {required this.streamId,
      required this.errorCode,
      required this.finalSize});

  @override
  int get frameType => 0x04;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x04);
    builder.add(VarInt.encode(streamId));
    builder.add(VarInt.encode(errorCode));
    builder.add(VarInt.encode(finalSize));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x05 STOP_SENDING
// ---------------------------------------------------------------------------
/// A STOP_SENDING frame (RFC 9000 Section 19.5).
class StopSendingFrame extends Frame {
  final int streamId;
  final int errorCode;

  StopSendingFrame({required this.streamId, required this.errorCode});

  @override
  int get frameType => 0x05;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x05);
    builder.add(VarInt.encode(streamId));
    builder.add(VarInt.encode(errorCode));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x06 CRYPTO
// ---------------------------------------------------------------------------
/// A CRYPTO frame (RFC 9000 Section 19.6).
class CryptoFrame extends Frame {
  final int offset;
  final List<int> data;

  CryptoFrame({required this.offset, required this.data});

  @override
  int get frameType => 0x06;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x06);
    builder.add(VarInt.encode(offset));
    builder.add(VarInt.encode(data.length));
    builder.add(data);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x07 NEW_TOKEN
// ---------------------------------------------------------------------------
/// A NEW_TOKEN frame (RFC 9000 Section 19.7).
class NewTokenFrame extends Frame {
  final List<int> token;

  NewTokenFrame({required this.token});

  @override
  int get frameType => 0x07;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x07);
    builder.add(VarInt.encode(token.length));
    builder.add(token);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x08-0x0f STREAM
// ---------------------------------------------------------------------------
/// A STREAM frame (RFC 9000 Section 19.8).
class StreamFrame extends Frame {
  final int streamId;
  final List<int> data;
  final int? offset;
  final bool fin;
  final bool hasExplicitLength;

  StreamFrame({
    required this.streamId,
    required this.data,
    this.offset,
    this.fin = false,
    this.hasExplicitLength = true,
  });

  @override
  int get frameType {
    var type = 0x08;
    if (fin) type |= 0x01;
    if (hasExplicitLength) type |= 0x02;
    if (offset != null) type |= 0x04;
    return type;
  }

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(frameType);
    builder.add(VarInt.encode(streamId));
    if (offset != null) {
      builder.add(VarInt.encode(offset!));
    }
    if (hasExplicitLength) {
      builder.add(VarInt.encode(data.length));
    }
    builder.add(data);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x10 MAX_DATA
// ---------------------------------------------------------------------------
/// A MAX_DATA frame (RFC 9000 Section 19.9).
class MaxDataFrame extends Frame {
  final int maxData;
  MaxDataFrame({required this.maxData});
  @override
  int get frameType => 0x10;
  @override
  Uint8List serialize() =>
      Uint8List.fromList([0x10, ...VarInt.encode(maxData)]);
}

// ---------------------------------------------------------------------------
// 0x11 MAX_STREAM_DATA
// ---------------------------------------------------------------------------
/// A MAX_STREAM_DATA frame (RFC 9000 Section 19.10).
class MaxStreamDataFrame extends Frame {
  final int streamId;
  final int maxStreamData;

  MaxStreamDataFrame({required this.streamId, required this.maxStreamData});

  @override
  int get frameType => 0x11;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x11);
    builder.add(VarInt.encode(streamId));
    builder.add(VarInt.encode(maxStreamData));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x12 MAX_STREAMS (bidi), 0x13 MAX_STREAMS (uni)
// ---------------------------------------------------------------------------
/// A MAX_STREAMS frame (RFC 9000 Section 19.11).
class MaxStreamsFrame extends Frame {
  final int maxStreams;
  final bool isUnidirectional;

  MaxStreamsFrame({required this.maxStreams, required this.isUnidirectional});

  @override
  int get frameType => isUnidirectional ? 0x13 : 0x12;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(frameType);
    builder.add(VarInt.encode(maxStreams));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x14 DATA_BLOCKED
// ---------------------------------------------------------------------------
/// A DATA_BLOCKED frame (RFC 9000 Section 19.12).
class DataBlockedFrame extends Frame {
  final int maxData;
  DataBlockedFrame({required this.maxData});
  @override
  int get frameType => 0x14;
  @override
  Uint8List serialize() =>
      Uint8List.fromList([0x14, ...VarInt.encode(maxData)]);
}

// ---------------------------------------------------------------------------
// 0x15 STREAM_DATA_BLOCKED
// ---------------------------------------------------------------------------
/// A STREAM_DATA_BLOCKED frame (RFC 9000 Section 19.13).
class StreamDataBlockedFrame extends Frame {
  final int streamId;
  final int maxStreamData;

  StreamDataBlockedFrame({required this.streamId, required this.maxStreamData});

  @override
  int get frameType => 0x15;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x15);
    builder.add(VarInt.encode(streamId));
    builder.add(VarInt.encode(maxStreamData));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x16 STREAMS_BLOCKED (bidi), 0x17 STREAMS_BLOCKED (uni)
// ---------------------------------------------------------------------------
/// A STREAMS_BLOCKED frame (RFC 9000 Section 19.14).
class StreamsBlockedFrame extends Frame {
  final int maxStreams;
  final bool isUnidirectional;

  StreamsBlockedFrame(
      {required this.maxStreams, required this.isUnidirectional});

  @override
  int get frameType => isUnidirectional ? 0x17 : 0x16;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(frameType);
    builder.add(VarInt.encode(maxStreams));
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x18 NEW_CONNECTION_ID
// ---------------------------------------------------------------------------
/// A NEW_CONNECTION_ID frame (RFC 9000 Section 19.15).
class NewConnectionIdFrame extends Frame {
  final int sequenceNumber;
  final int retirePriorTo;
  final List<int> connectionId;
  final List<int> statelessResetToken; // 16 bytes

  NewConnectionIdFrame({
    required this.sequenceNumber,
    required this.retirePriorTo,
    required this.connectionId,
    required this.statelessResetToken,
  }) {
    if (statelessResetToken.length != 16) {
      throw ArgumentError('Stateless reset token must be 16 bytes');
    }
  }

  @override
  int get frameType => 0x18;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x18);
    builder.add(VarInt.encode(sequenceNumber));
    builder.add(VarInt.encode(retirePriorTo));
    builder.addByte(connectionId.length);
    builder.add(connectionId);
    builder.add(statelessResetToken);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x19 RETIRE_CONNECTION_ID
// ---------------------------------------------------------------------------
/// A RETIRE_CONNECTION_ID frame (RFC 9000 Section 19.16).
class RetireConnectionIdFrame extends Frame {
  final int sequenceNumber;
  RetireConnectionIdFrame({required this.sequenceNumber});
  @override
  int get frameType => 0x19;
  @override
  Uint8List serialize() =>
      Uint8List.fromList([0x19, ...VarInt.encode(sequenceNumber)]);
}

// ---------------------------------------------------------------------------
// 0x1a PATH_CHALLENGE
// ---------------------------------------------------------------------------
/// A PATH_CHALLENGE frame (RFC 9000 Section 19.17).
class PathChallengeFrame extends Frame {
  final Uint8List data; // 8 bytes

  PathChallengeFrame({List<int>? data})
      : data = data is Uint8List
            ? data
            : Uint8List.fromList(data ?? _generateRandomData()) {
    if (this.data.length != 8) {
      throw ArgumentError('PATH_CHALLENGE data must be 8 bytes');
    }
  }

  static Uint8List _generateRandomData() {
    final random = Random.secure();
    return Uint8List.fromList(
        List<int>.generate(8, (_) => random.nextInt(256)));
  }

  static PathChallengeFrame parse(Uint8List bytes) {
    if (bytes.length < 9) {
      throw ArgumentError('PATH_CHALLENGE frame requires at least 9 bytes');
    }
    return PathChallengeFrame(data: bytes.sublist(1, 9));
  }

  @override
  int get frameType => 0x1a;

  @override
  Uint8List serialize() => Uint8List.fromList([0x1a, ...data]);

  int get byteLength => 1 + 8;
}

// ---------------------------------------------------------------------------
// 0x1b PATH_RESPONSE
// ---------------------------------------------------------------------------
/// A PATH_RESPONSE frame (RFC 9000 Section 19.18).
class PathResponseFrame extends Frame {
  final Uint8List data; // 8 bytes

  PathResponseFrame({required List<int> data})
      : data = data is Uint8List ? data : Uint8List.fromList(data) {
    if (this.data.length != 8) {
      throw ArgumentError('PATH_RESPONSE data must be 8 bytes');
    }
  }

  static PathResponseFrame parse(Uint8List bytes) {
    if (bytes.length < 9) {
      throw ArgumentError('PATH_RESPONSE frame requires at least 9 bytes');
    }
    return PathResponseFrame(data: bytes.sublist(1, 9));
  }

  @override
  int get frameType => 0x1b;

  @override
  Uint8List serialize() => Uint8List.fromList([0x1b, ...data]);

  int get byteLength => 1 + 8;
}

// ---------------------------------------------------------------------------
// 0x1c CONNECTION_CLOSE (transport)
// ---------------------------------------------------------------------------
/// A CONNECTION_CLOSE frame for transport errors (RFC 9000 Section 19.19).
class ConnectionCloseFrame extends Frame {
  final int errorCode;
  final int? offendingFrameType;
  final String reasonPhrase;

  ConnectionCloseFrame({
    required this.errorCode,
    this.offendingFrameType,
    this.reasonPhrase = '',
  });

  @override
  int get frameType => 0x1c;
  @override
  bool get isAckEliciting => false;
  @override
  bool get isInFlight => false;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x1c);
    builder.add(VarInt.encode(errorCode));
    builder.add(VarInt.encode(offendingFrameType ?? 0));
    final rp = reasonPhrase.codeUnits;
    builder.add(VarInt.encode(rp.length));
    builder.add(rp);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x1d CONNECTION_CLOSE (application)
// ---------------------------------------------------------------------------
/// A CONNECTION_CLOSE frame for application errors (RFC 9000 Section 19.19).
class ApplicationCloseFrame extends Frame {
  final int errorCode;
  final String reasonPhrase;

  ApplicationCloseFrame({required this.errorCode, this.reasonPhrase = ''});

  @override
  int get frameType => 0x1d;
  @override
  bool get isAckEliciting => false;
  @override
  bool get isInFlight => false;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0x1d);
    builder.add(VarInt.encode(errorCode));
    final rp = reasonPhrase.codeUnits;
    builder.add(VarInt.encode(rp.length));
    builder.add(rp);
    return Uint8List.fromList(builder.toBytes());
  }
}

// ---------------------------------------------------------------------------
// 0x1e HANDSHAKE_DONE
// ---------------------------------------------------------------------------
/// A HANDSHAKE_DONE frame (RFC 9000 Section 19.20).
class HandshakeDoneFrame extends Frame {
  HandshakeDoneFrame();
  @override
  int get frameType => 0x1e;
  @override
  Uint8List serialize() => Uint8List(1)..[0] = 0x1e;
}

// ---------------------------------------------------------------------------
// 0x30/0x31 DATAGRAM (RFC 9221)
// ---------------------------------------------------------------------------
/// A DATAGRAM frame (RFC 9221 Section 4).
///
/// QUIC datagrams provide an unreliable, unordered message abstraction.
/// Unlike STREAM frames, datagrams are not retransmitted and are not subject
/// to QUIC flow control. They are still limited by congestion control and the
/// negotiated `max_datagram_frame_size`.
///
/// Two frame types are defined:
/// - `0x30`: DATAGRAM with no length field (data extends to end of packet).
/// - `0x31`: DATAGRAM with a length prefix (allows coalescing with other frames).
class DatagramFrame extends Frame {
  final Uint8List data;
  final bool hasLength;

  DatagramFrame({required this.data, this.hasLength = false});

  @override
  int get frameType => hasLength ? 0x31 : 0x30;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(frameType);
    if (hasLength) {
      builder.add(VarInt.encode(data.length));
    }
    builder.add(data);
    return Uint8List.fromList(builder.toBytes());
  }

  /// Returns the wire-format byte length of this frame.
  int getByteLength() {
    return 1 +
        (hasLength ? VarInt.encode(data.length).length : 0) +
        data.length;
  }
}

// ---------------------------------------------------------------------------
// 0xaf ACK_FREQUENCY (RFC 9298)
// ---------------------------------------------------------------------------
/// An ACK_FREQUENCY frame allows a receiver to request the sender to change
/// its acknowledgement frequency.
///
/// Wire format:
/// ```
/// ACK_FREQUENCY Frame {
///   Frame Type (i) = 0xaf,
///   Sequence Number (i),
///   Requested Ack Eliciting Threshold (i),
///   Requested Max Ack Delay (i),
///   Ignore Order (8),
/// }
/// ```
class AckFrequencyFrame extends Frame {
  final int sequenceNumber;
  final int requestedAckElicitingThreshold;
  final int requestedMaxAckDelay;
  final bool ignoreOrder;

  AckFrequencyFrame({
    required this.sequenceNumber,
    required this.requestedAckElicitingThreshold,
    required this.requestedMaxAckDelay,
    this.ignoreOrder = false,
  });

  @override
  int get frameType => 0xaf;

  @override
  bool get isAckEliciting => true;

  @override
  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.addByte(0xaf);
    builder.add(VarInt.encode(sequenceNumber));
    builder.add(VarInt.encode(requestedAckElicitingThreshold));
    builder.add(VarInt.encode(requestedMaxAckDelay));
    builder.addByte(ignoreOrder ? 1 : 0);
    return builder.toBytes();
  }

  /// Wire-format byte length.
  int getByteLength() {
    return 1 +
        VarInt.encode(sequenceNumber).length +
        VarInt.encode(requestedAckElicitingThreshold).length +
        VarInt.encode(requestedMaxAckDelay).length +
        1;
  }
}

// ---------------------------------------------------------------------------
// Frame Codec
// ---------------------------------------------------------------------------
/// Codec for serializing and parsing QUIC frames (RFC 9000 Section 12 and 19).
///
/// [FrameCodec] provides static helpers to convert between [Frame] objects and
/// their wire-format byte representation. It is used by the packet builder when
/// constructing outgoing packets and by the packet receiver when decoding
/// incoming frames.
///
/// ## Example
/// ```dart
/// final ping = PingFrame();
/// final bytes = FrameCodec.serialize(ping);
/// final (frame, offset) = FrameCodec.parse(bytes);
/// ```
///
/// See also:
/// - [Frame] — the abstract base class for all QUIC frames.
/// - [PacketProtector] — encrypts packets containing serialized frames.
/// - RFC 9000 Section 19 — frame types and formats.
class FrameCodec {
  /// Serialize a frame to bytes.
  static Uint8List serialize(Frame frame) => frame.serialize();

  /// Parse a single frame from [bytes] starting at [offset].
  /// Returns the parsed frame and the new offset.
  static (Frame, int) parse(Uint8List bytes, {int offset = 0}) {
    if (offset >= bytes.length) throw ArgumentError('Offset out of bounds');
    final firstByte = bytes[offset];
    final frame = _parseFrame(firstByte, bytes, offset);
    return (frame, offset + _frameLength(frame, bytes, offset));
  }

  /// Returns the byte length of the frame starting at [offset].
  static int frameLength(Uint8List bytes, {int offset = 0}) {
    final frame = _parseFrame(bytes[offset], bytes, offset);
    return _frameLength(frame, bytes, offset);
  }

  // SECURITY: Helper for safe buffer access during frame parsing.
  static Uint8List _safeSublist(Uint8List bytes, int start, int length,
      {int? maxLength}) {
    if (start < 0 || start > bytes.length) {
      throw ArgumentError('Invalid start offset');
    }
    if (length < 0) {
      throw ArgumentError('Invalid length');
    }
    if (start + length > bytes.length) {
      throw ArgumentError('Frame data exceeds buffer bounds');
    }
    if (maxLength != null && length > maxLength) {
      throw ArgumentError('Frame data exceeds maximum allowed size');
    }
    return bytes.sublist(start, start + length);
  }

  static Frame _parseFrame(int type, Uint8List bytes, int offset) {
    int readVarInt(int off) {
      return VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes + off);
    }

    int varIntLength(int off) => VarInt.decodeLength(bytes[off]);

    int pos = offset + 1;

    switch (type) {
      case 0x00: // PADDING
        return PaddingFrame(length: 1);
      case 0x01: // PING
        return PingFrame();
      case 0x02: // ACK
      case 0x03: // ACK_ECN
        final largestAcknowledged = readVarInt(pos);
        pos += varIntLength(pos);
        final ackDelay = readVarInt(pos);
        pos += varIntLength(pos);
        final ackRangeCount = readVarInt(pos);
        pos += varIntLength(pos);
        // SECURITY: Limit ACK ranges to prevent CPU/memory exhaustion DoS.
        if (ackRangeCount > 256) {
          throw ArgumentError('ACK frame has too many ranges');
        }
        final firstRangeLength = readVarInt(pos);
        pos += varIntLength(pos);
        final ranges = <AckRange>[];
        if (ackRangeCount > 0) {
          ranges.add(AckRange(gap: 0, length: firstRangeLength));
          for (var i = 1; i < ackRangeCount; i++) {
            if (pos >= bytes.length) {
              throw ArgumentError('ACK frame truncated while parsing ranges');
            }
            final gap = readVarInt(pos);
            pos += varIntLength(pos);
            final length = readVarInt(pos);
            pos += varIntLength(pos);
            ranges.add(AckRange(gap: gap, length: length));
          }
        }
        if (type == 0x03) {
          final ect0Count = readVarInt(pos);
          pos += varIntLength(pos);
          final ect1Count = readVarInt(pos);
          pos += varIntLength(pos);
          final ceCount = readVarInt(pos);
          return AckEcnFrame(
            largestAcknowledged: largestAcknowledged,
            ackDelay: ackDelay,
            ackRanges: ranges,
            ect0Count: ect0Count,
            ect1Count: ect1Count,
            ceCount: ceCount,
          );
        }
        return AckFrame(
          largestAcknowledged: largestAcknowledged,
          ackDelay: ackDelay,
          ackRanges: ranges,
        );
      case 0x04: // RESET_STREAM
        final streamId = readVarInt(pos);
        pos += varIntLength(pos);
        final errorCode = readVarInt(pos);
        pos += varIntLength(pos);
        final finalSize = readVarInt(pos);
        return ResetStreamFrame(
          streamId: streamId,
          errorCode: errorCode,
          finalSize: finalSize,
        );
      case 0x05: // STOP_SENDING
        final streamId = readVarInt(pos);
        pos += varIntLength(pos);
        final errorCode = readVarInt(pos);
        return StopSendingFrame(
          streamId: streamId,
          errorCode: errorCode,
        );
      case 0x06: // CRYPTO
        final offsetValue = readVarInt(pos);
        pos += varIntLength(pos);
        final lengthValue = readVarInt(pos);
        pos += varIntLength(pos);
        final data =
            _safeSublist(bytes, pos, lengthValue, maxLength: 16 * 1024 * 1024);
        return CryptoFrame(offset: offsetValue, data: data);
      case 0x07: // NEW_TOKEN
        final lengthValue = readVarInt(pos);
        pos += varIntLength(pos);
        final token = _safeSublist(bytes, pos, lengthValue, maxLength: 4096);
        return NewTokenFrame(token: token);
      case 0x08:
      case 0x09:
      case 0x0a:
      case 0x0b:
      case 0x0c:
      case 0x0d:
      case 0x0e:
      case 0x0f: // STREAM
        final fin = (type & 0x01) != 0;
        final hasLen = (type & 0x02) != 0;
        final hasOff = (type & 0x04) != 0;

        final streamId = readVarInt(pos);
        pos += varIntLength(pos);

        int? streamOffset;
        if (hasOff) {
          streamOffset = readVarInt(pos);
          pos += varIntLength(pos);
        }

        int lengthValue;
        if (hasLen) {
          lengthValue = readVarInt(pos);
          pos += varIntLength(pos);
          if (pos + lengthValue > bytes.length) {
            throw ArgumentError('STREAM frame data exceeds buffer bounds');
          }
          if (lengthValue > 64 * 1024) {
            throw ArgumentError('STREAM frame data too large');
          }
        } else {
          lengthValue = bytes.length - pos;
        }

        final data = _safeSublist(bytes, pos, lengthValue);
        return StreamFrame(
          streamId: streamId,
          data: data,
          offset: streamOffset,
          fin: fin,
          hasExplicitLength: hasLen,
        );
      case 0x10: // MAX_DATA
        return MaxDataFrame(maxData: readVarInt(pos));
      case 0x11: // MAX_STREAM_DATA
        final streamId = readVarInt(pos);
        pos += varIntLength(pos);
        final maxStreamData = readVarInt(pos);
        return MaxStreamDataFrame(
            streamId: streamId, maxStreamData: maxStreamData);
      case 0x12: // MAX_STREAMS (bidi)
        return MaxStreamsFrame(
            maxStreams: readVarInt(pos), isUnidirectional: false);
      case 0x13: // MAX_STREAMS (uni)
        return MaxStreamsFrame(
            maxStreams: readVarInt(pos), isUnidirectional: true);
      case 0x14: // DATA_BLOCKED
        return DataBlockedFrame(maxData: readVarInt(pos));
      case 0x15: // STREAM_DATA_BLOCKED
        final streamId = readVarInt(pos);
        pos += varIntLength(pos);
        final maxStreamData = readVarInt(pos);
        return StreamDataBlockedFrame(
            streamId: streamId, maxStreamData: maxStreamData);
      case 0x16: // STREAMS_BLOCKED (bidi)
        return StreamsBlockedFrame(
            maxStreams: readVarInt(pos), isUnidirectional: false);
      case 0x17: // STREAMS_BLOCKED (uni)
        return StreamsBlockedFrame(
            maxStreams: readVarInt(pos), isUnidirectional: true);
      case 0x18: // NEW_CONNECTION_ID
        final sequenceNumber = readVarInt(pos);
        pos += varIntLength(pos);
        final retirePriorTo = readVarInt(pos);
        pos += varIntLength(pos);
        final connectionIdLength = bytes[pos++];
        if (connectionIdLength > 20) {
          throw ArgumentError('Connection ID too long (max 20 bytes)');
        }
        final connectionId = _safeSublist(bytes, pos, connectionIdLength);
        pos += connectionIdLength;
        final statelessResetToken = _safeSublist(bytes, pos, 16);
        pos += 16;
        return NewConnectionIdFrame(
          sequenceNumber: sequenceNumber,
          retirePriorTo: retirePriorTo,
          connectionId: connectionId,
          statelessResetToken: statelessResetToken,
        );
      case 0x19: // RETIRE_CONNECTION_ID
        final sequenceNumber = readVarInt(pos);
        pos += varIntLength(pos);
        return RetireConnectionIdFrame(sequenceNumber: sequenceNumber);
      case 0x1a: // PATH_CHALLENGE
        final data = _safeSublist(bytes, pos, 8);
        return PathChallengeFrame(data: data);
      case 0x1b: // PATH_RESPONSE
        final data = _safeSublist(bytes, pos, 8);
        return PathResponseFrame(data: data);
      case 0x1c: // CONNECTION_CLOSE (transport)
        final errorCode = readVarInt(pos);
        pos += varIntLength(pos);
        final offendingFrameType = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseLength = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseBytes =
            _safeSublist(bytes, pos, reasonPhraseLength, maxLength: 1024);
        final reasonPhrase = String.fromCharCodes(reasonPhraseBytes);
        return ConnectionCloseFrame(
          errorCode: errorCode,
          offendingFrameType: offendingFrameType,
          reasonPhrase: reasonPhrase,
        );
      case 0x1d: // CONNECTION_CLOSE (application)
        final errorCode = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseLength = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseBytes =
            _safeSublist(bytes, pos, reasonPhraseLength, maxLength: 1024);
        final reasonPhrase = String.fromCharCodes(reasonPhraseBytes);
        return ApplicationCloseFrame(
          errorCode: errorCode,
          reasonPhrase: reasonPhrase,
        );
      case 0x1e: // HANDSHAKE_DONE
        return HandshakeDoneFrame();
      case 0x30: // DATAGRAM (no length)
        final data = _safeSublist(bytes, pos, bytes.length - pos);
        return DatagramFrame(data: data, hasLength: false);
      case 0x31: // DATAGRAM (with length)
        final lengthValue = readVarInt(pos);
        pos += varIntLength(pos);
        final data = _safeSublist(bytes, pos, lengthValue);
        return DatagramFrame(data: data, hasLength: true);
      case 0xaf: // ACK_FREQUENCY (RFC 9298)
        final seqNum = readVarInt(pos);
        pos += varIntLength(pos);
        final threshold = readVarInt(pos);
        pos += varIntLength(pos);
        final maxDelay = readVarInt(pos);
        pos += varIntLength(pos);
        final ignoreOrder = _safeSublist(bytes, pos, 1)[0] != 0;
        return AckFrequencyFrame(
          sequenceNumber: seqNum,
          requestedAckElicitingThreshold: threshold,
          requestedMaxAckDelay: maxDelay,
          ignoreOrder: ignoreOrder,
        );
      default:
        throw UnsupportedError(
            'Frame parsing not yet implemented for type 0x${type.toRadixString(16)}');
    }
  }

  static int _frameLength(Frame frame, Uint8List bytes, int offset) {
    return frame.serialize().length;
  }
}

// MARKER

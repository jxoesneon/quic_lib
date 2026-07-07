import 'dart:math';
import 'dart:typed_data';
import 'transport_error_codes.dart';
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
///
/// PADDING frames carry no semantic information; they simply increase the
/// size of a packet. They are used to pad Initial packets to the minimum
/// 1200-byte datagram size required by RFC 9000 Section 14.1, and to
/// prevent traffic analysis by obscuring the true payload length.
class PaddingFrame extends Frame {
  /// The number of zero bytes this frame occupies on the wire.
  final int length;

  /// Creates a [PaddingFrame] that serializes to [length] zero bytes.
  ///
  /// [length] defaults to 1. The [FrameCodec] parser automatically coalesces
  /// consecutive 0x00 bytes into a single [PaddingFrame] with the appropriate
  /// [length].
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
///
/// A PING frame elicits an ACK from the peer and can be used to:
/// - Keep the connection alive when there is no application data to send.
/// - Probe whether the path is still alive before a PTO fires.
/// - Prevent the peer's idle timeout from expiring.
///
/// The frame carries no data beyond the 0x01 type byte.
class PingFrame extends Frame {
  /// Creates a [PingFrame].
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
///
/// Abruptly terminates the sending part of a stream. The receiver discards
/// all buffered data for the stream and notifies the application.
///
/// See also:
/// - [StopSendingFrame] — requests the peer to stop sending on a stream.
/// - RFC 9000 Section 3.1 — stream send-side state machine.
class ResetStreamFrame extends Frame {
  /// The stream to reset.
  final int streamId;

  /// Application-defined error code explaining why the stream is being reset.
  final int errorCode;

  /// The final byte offset of the stream, used for flow-control accounting.
  final int finalSize;

  /// Creates a [ResetStreamFrame] for [streamId] with the given [errorCode]
  /// and [finalSize].
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
///
/// Requests the peer to stop sending data on [streamId]. The peer responds
/// by sending a RESET_STREAM frame for that stream. This is used when the
/// application is no longer interested in receiving data but the stream was
/// opened by the remote side.
///
/// See also:
/// - [ResetStreamFrame] — abruptly terminates a sending stream.
/// - RFC 9000 Section 3.5 — receiving STOP_SENDING.
class StopSendingFrame extends Frame {
  /// The stream on which the sender should stop sending.
  final int streamId;

  /// Application-defined error code passed to the peer in the resulting
  /// RESET_STREAM frame.
  final int errorCode;

  /// Creates a [StopSendingFrame] for [streamId] with [errorCode].
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
///
/// Carries TLS handshake bytes within a QUIC packet. Unlike STREAM frames,
/// CRYPTO frames have no stream-level flow control; they are constrained only
/// by the packet number space they appear in (Initial, Handshake, or 1-RTT).
///
/// The [offset] and length of [data] together define a byte range in the
/// cryptographic byte stream for that packet number space. Gaps or overlapping
/// deliveries are reassembled by the crypto frame assembler.
class CryptoFrame extends Frame {
  /// Byte offset of [data] within the TLS handshake byte stream.
  final int offset;

  /// TLS record bytes carried by this frame.
  final List<int> data;

  /// Creates a [CryptoFrame] with the given [offset] and [data].
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
///
/// Sent by the server to provide the client with a token that can be used in
/// the Initial packet of a future connection to the same server. This allows
/// the server to validate the client's address without a round trip.
///
/// See also:
/// - RFC 9000 Section 8.1.3 — using tokens from NEW_TOKEN.
class NewTokenFrame extends Frame {
  /// An opaque token that the client can use in a future Initial packet.
  final List<int> token;

  /// Creates a [NewTokenFrame] carrying [token].
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
///
/// STREAM frames carry application data for a specific stream. The frame
/// type byte encodes three flags in its low-order bits:
/// - Bit 0 (0x01): **FIN** — this frame contains the final byte of the stream.
/// - Bit 1 (0x02): **LEN** — an explicit length field precedes the data.
/// - Bit 2 (0x04): **OFF** — an explicit offset field precedes the data.
///
/// The resulting type is in the range 0x08–0x0f depending on which flags
/// are set.
class StreamFrame extends Frame {
  /// The QUIC stream identifier this frame belongs to.
  final int streamId;

  /// The application payload bytes carried by this frame.
  final List<int> data;

  /// Byte offset of [data] within the stream, or `null` if omitted.
  ///
  /// When `null`, the receiver treats the offset as 0 (allowed only for
  /// the first STREAM frame on a stream when no offset field is present).
  final int? offset;

  /// Whether this is the final frame on the stream.
  ///
  /// When `true`, the FIN bit (0x01) is set in [frameType] and the peer
  /// knows the total number of bytes in the stream.
  final bool fin;

  /// Whether a length prefix is included in the wire encoding.
  ///
  /// When `true` the LEN bit (0x02) is set and the data length is written
  /// before the payload, allowing multiple frames to be coalesced into
  /// a single packet. Defaults to `true`.
  final bool hasExplicitLength;

  /// Creates a [StreamFrame] carrying [data] for [streamId].
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
///
/// Increases the connection-level flow-control limit. [maxData] is the
/// maximum number of bytes the sender is permitted to send on the entire
/// connection (the sum of all stream data). The receiver sends this frame
/// to grant the peer more send credit.
class MaxDataFrame extends Frame {
  /// New connection-level send limit in bytes.
  final int maxData;

  /// Creates a [MaxDataFrame] advertising [maxData] as the new limit.
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
///
/// Increases the per-stream flow-control limit for [streamId]. The sender
/// must not transmit more bytes on [streamId] than the limit communicated
/// by this frame.
class MaxStreamDataFrame extends Frame {
  /// The stream whose send limit is being updated.
  final int streamId;

  /// New per-stream send limit in bytes.
  final int maxStreamData;

  /// Creates a [MaxStreamDataFrame] for [streamId] with [maxStreamData].
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
///
/// Increases the peer's stream concurrency limit. Two subtypes exist:
/// - Frame type 0x12: bidirectional streams.
/// - Frame type 0x13: unidirectional streams.
///
/// [isUnidirectional] selects the subtype. [maxStreams] is the new cumulative
/// count of streams the peer is allowed to open (not a delta).
class MaxStreamsFrame extends Frame {
  /// New cumulative stream-count limit.
  final int maxStreams;

  /// `true` for unidirectional streams (0x13); `false` for bidirectional (0x12).
  final bool isUnidirectional;

  /// Creates a [MaxStreamsFrame] for the given [maxStreams] and direction.
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
///
/// Sent by a sender to indicate it is blocked at the connection-level
/// flow-control limit [maxData]. This serves as a hint to the receiver that
/// it should send a [MaxDataFrame] to increase the limit.
class DataBlockedFrame extends Frame {
  /// The connection-level limit at which the sender is blocked.
  final int maxData;

  /// Creates a [DataBlockedFrame] reporting [maxData] as the blocking limit.
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
///
/// Sent when a sender is blocked on a per-stream flow-control limit. The
/// [maxStreamData] value is the limit that is blocking the sender, providing
/// the receiver a hint to send a [MaxStreamDataFrame] to unblock it.
class StreamDataBlockedFrame extends Frame {
  /// The stream that is blocked.
  final int streamId;

  /// The per-stream limit at which the sender is blocked.
  final int maxStreamData;

  /// Creates a [StreamDataBlockedFrame] for [streamId] at [maxStreamData].
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
///
/// Sent when a sender wants to open a stream but has reached the peer's
/// stream concurrency limit. Two subtypes exist (bidirectional 0x16 and
/// unidirectional 0x17). [maxStreams] is the limit that is blocking the
/// sender. The receiver should respond with a [MaxStreamsFrame].
class StreamsBlockedFrame extends Frame {
  /// The stream-count limit at which the sender is blocked.
  final int maxStreams;

  /// `true` for unidirectional streams (0x17); `false` for bidirectional (0x16).
  final bool isUnidirectional;

  /// Creates a [StreamsBlockedFrame] for the given [maxStreams] and direction.
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
///
/// Provides the peer with an additional connection ID that can be used to
/// send packets to this endpoint. Multiple connection IDs improve privacy
/// by preventing on-path observers from linking packets across path changes
/// or migrations.
///
/// The [retirePriorTo] field instructs the peer to retire any connection IDs
/// with a sequence number lower than the given value, bounding the number
/// of active IDs.
class NewConnectionIdFrame extends Frame {
  /// Monotonically increasing identifier for this connection ID offer.
  final int sequenceNumber;

  /// Sequence number below which the peer should retire connection IDs.
  final int retirePriorTo;

  /// The new connection ID bytes (1–20 bytes per RFC 9000 Section 17.2).
  final List<int> connectionId;

  /// 16-byte stateless reset token associated with [connectionId].
  final List<int> statelessResetToken; // 16 bytes

  /// Creates a [NewConnectionIdFrame].
  ///
  /// Throws [ArgumentError] if [statelessResetToken] is not exactly 16 bytes.
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
///
/// Informs the peer that the sender will no longer use the connection ID with
/// the given [sequenceNumber]. The peer may reuse the retired slot for a
/// future [NewConnectionIdFrame]. Retiring a connection ID does not affect
/// the current active connection ID.
class RetireConnectionIdFrame extends Frame {
  /// Sequence number of the connection ID to retire, as assigned by the peer
  /// in the corresponding [NewConnectionIdFrame].
  final int sequenceNumber;

  /// Creates a [RetireConnectionIdFrame] retiring [sequenceNumber].
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
///
/// Used to verify reachability of a path during connection migration.
/// The sender chooses a random 8-byte [data] value. The peer must echo the
/// same bytes in a [PathResponseFrame]. A matching response confirms
/// bidirectional reachability on the new path.
///
/// See also:
/// - [PathResponseFrame] — the required reply to a PATH_CHALLENGE.
/// - RFC 9000 Section 8.2 — path validation procedure.
class PathChallengeFrame extends Frame {
  /// 8-byte random challenge value.
  final Uint8List data; // 8 bytes

  /// Creates a [PathChallengeFrame].
  ///
  /// If [data] is omitted, a cryptographically random 8-byte value is
  /// generated automatically. Throws [ArgumentError] if [data] is provided
  /// but its length is not exactly 8 bytes.
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

  /// Parses a PATH_CHALLENGE frame from [bytes] starting at offset 0.
  ///
  /// [bytes] must be at least 9 bytes: 1 type byte (0x1a) followed by 8 bytes
  /// of challenge data. Throws [ArgumentError] if the buffer is too short.
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

  /// Wire-format byte length of this frame: 1 type byte + 8 data bytes = 9.
  int get byteLength => 1 + 8;
}

// ---------------------------------------------------------------------------
// 0x1b PATH_RESPONSE
// ---------------------------------------------------------------------------
/// A PATH_RESPONSE frame (RFC 9000 Section 19.18).
///
/// Sent in reply to a [PathChallengeFrame] to confirm that the sender can
/// reach the challenger on this path. The [data] field must equal the
/// 8-byte value from the corresponding PATH_CHALLENGE.
///
/// See also:
/// - [PathChallengeFrame] — the challenge that triggers this response.
/// - RFC 9000 Section 8.2.2 — validating a path with PATH_RESPONSE.
class PathResponseFrame extends Frame {
  /// 8-byte echo of the corresponding [PathChallengeFrame.data].
  final Uint8List data; // 8 bytes

  /// Creates a [PathResponseFrame] echoing [data] from the challenge.
  ///
  /// Throws [ArgumentError] if [data] is not exactly 8 bytes.
  PathResponseFrame({required List<int> data})
      : data = data is Uint8List ? data : Uint8List.fromList(data) {
    if (this.data.length != 8) {
      throw ArgumentError('PATH_RESPONSE data must be 8 bytes');
    }
  }

  /// Parses a PATH_RESPONSE frame from [bytes] starting at offset 0.
  ///
  /// [bytes] must be at least 9 bytes: 1 type byte (0x1b) followed by 8 bytes
  /// of response data. Throws [ArgumentError] if the buffer is too short.
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

  /// Wire-format byte length of this frame: 1 type byte + 8 data bytes = 9.
  int get byteLength => 1 + 8;
}

// ---------------------------------------------------------------------------
// 0x1c CONNECTION_CLOSE (transport)
// ---------------------------------------------------------------------------
/// A CONNECTION_CLOSE frame for transport errors (RFC 9000 Section 19.19).
///
/// Signals that the connection is being terminated due to a transport-level
/// error. The [errorCode] identifies the error using QUIC transport error codes
/// (RFC 9000 Section 20.1). The optional [offendingFrameType] names the frame
/// type that triggered the error, and [reasonPhrase] carries a human-readable
/// explanation.
///
/// See also:
/// - [ApplicationCloseFrame] — terminates the connection due to an
///   application-level error (frame type 0x1d).
/// - RFC 9000 Section 10.2 — immediate connection close.
class ConnectionCloseFrame extends Frame {
  /// QUIC transport error code (RFC 9000 Section 20.1).
  final int errorCode;

  /// Frame type that triggered the error, if known. May be `null`.
  final int? offendingFrameType;

  /// Human-readable explanation of the error (UTF-8, may be empty).
  final String reasonPhrase;

  /// Creates a [ConnectionCloseFrame].
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
///
/// Terminates the connection due to an application-level error (frame type
/// 0x1d). The [errorCode] is defined by the application protocol (e.g.,
/// HTTP/3 error codes). Unlike [ConnectionCloseFrame], this variant does not
/// carry an offending frame type.
///
/// See also:
/// - [ConnectionCloseFrame] — transport-error variant (frame type 0x1c).
/// - RFC 9000 Section 10.2.3 — immediate connection close for application errors.
class ApplicationCloseFrame extends Frame {
  /// Application protocol error code.
  final int errorCode;

  /// Human-readable explanation of the error (UTF-8, may be empty).
  final String reasonPhrase;

  /// Creates an [ApplicationCloseFrame] with the given [errorCode] and
  /// optional [reasonPhrase].
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
///
/// This frame is sent by the server immediately after the TLS handshake
/// completes to signal to the client that handshake confirmation is finished
/// and that Handshake keys may be discarded. Only the server sends this frame;
/// receiving it from a client is a protocol violation.
///
/// The frame contains only the 0x1e type byte with no additional fields.
class HandshakeDoneFrame extends Frame {
  /// Creates a [HandshakeDoneFrame].
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
///   Reordering Threshold (i),
/// }
/// ```
class AckFrequencyFrame extends Frame {
  final int sequenceNumber;
  final int requestedAckElicitingThreshold;
  final int requestedMaxAckDelay;
  final int reorderingThreshold;

  AckFrequencyFrame({
    required this.sequenceNumber,
    required this.requestedAckElicitingThreshold,
    required this.requestedMaxAckDelay,
    this.reorderingThreshold = 1,
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
    builder.add(VarInt.encode(reorderingThreshold));
    return builder.toBytes();
  }

  /// Wire-format byte length.
  int getByteLength() {
    return 1 +
        VarInt.encode(sequenceNumber).length +
        VarInt.encode(requestedAckElicitingThreshold).length +
        VarInt.encode(requestedMaxAckDelay).length +
        VarInt.encode(reorderingThreshold).length;
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

  /// Parse all frames from [bytes] and return them as a list.
  ///
  /// Throws if any frame is malformed or if trailing bytes cannot be parsed.
  static List<Frame> parseAll(Uint8List bytes) {
    final frames = <Frame>[];
    var offset = 0;
    while (offset < bytes.length) {
      final (frame, newOffset) = parse(bytes, offset: offset);
      frames.add(frame);
      offset = newOffset;
    }
    return frames;
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
        // Coalesce consecutive PADDING bytes into a single frame. This avoids
        // creating thousands of tiny frames when a packet is padded to the
        // RFC 9000 minimum Initial packet size.
        var length = 1;
        while (
            offset + length < bytes.length && bytes[offset + length] == 0x00) {
          length++;
        }
        return PaddingFrame(length: length);
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
        // Defensive upper bound for datagram payloads; the negotiated
        // max_datagram_frame_size should be smaller in practice.
        final data = _safeSublist(bytes, pos, bytes.length - pos,
            maxLength: 1024 * 1024);
        return DatagramFrame(data: data, hasLength: false);
      case 0x31: // DATAGRAM (with length)
        final lengthValue = readVarInt(pos);
        pos += varIntLength(pos);
        final data =
            _safeSublist(bytes, pos, lengthValue, maxLength: 1024 * 1024);
        return DatagramFrame(data: data, hasLength: true);
      case 0xaf: // ACK_FREQUENCY (RFC 9298)
        final seqNum = readVarInt(pos);
        pos += varIntLength(pos);
        final threshold = readVarInt(pos);
        pos += varIntLength(pos);
        final maxDelay = readVarInt(pos);
        pos += varIntLength(pos);
        final reorderingThreshold = readVarInt(pos);
        return AckFrequencyFrame(
          sequenceNumber: seqNum,
          requestedAckElicitingThreshold: threshold,
          requestedMaxAckDelay: maxDelay,
          reorderingThreshold: reorderingThreshold,
        );
      default:
        // RFC 9000 Section 12.4: An endpoint MUST treat the receipt of a frame
        // of unknown type as a connection error of type FRAME_ENCODING_ERROR.
        throw FrameEncodingError(
            'Unknown frame type: 0x${type.toRadixString(16)}');
    }
  }

  static int _frameLength(Frame frame, Uint8List bytes, int offset) {
    return frame.serialize().length;
  }
}

// MARKER

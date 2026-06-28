import 'dart:typed_data';
import 'varint.dart';

/// Base class for all QUIC frames.
abstract class Frame {
  int get frameType;
  Uint8List serialize();
}

// ---------------------------------------------------------------------------
// 0x00 PADDING
// ---------------------------------------------------------------------------
/// A PADDING frame (RFC 9000 Section 19.1).
class PaddingFrame implements Frame {
  final int length;
  PaddingFrame({this.length = 1});
  @override
  int get frameType => 0x00;
  @override
  Uint8List serialize() => Uint8List(length);
}

// ---------------------------------------------------------------------------
// 0x01 PING
// ---------------------------------------------------------------------------
/// A PING frame (RFC 9000 Section 19.2).
class PingFrame implements Frame {
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
class AckFrame implements Frame {
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
class ResetStreamFrame implements Frame {
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
class StopSendingFrame implements Frame {
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
class CryptoFrame implements Frame {
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
class NewTokenFrame implements Frame {
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
class StreamFrame implements Frame {
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
class MaxDataFrame implements Frame {
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
class MaxStreamDataFrame implements Frame {
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
class MaxStreamsFrame implements Frame {
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
class DataBlockedFrame implements Frame {
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
class StreamDataBlockedFrame implements Frame {
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
class StreamsBlockedFrame implements Frame {
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
class NewConnectionIdFrame implements Frame {
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
class RetireConnectionIdFrame implements Frame {
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
class PathChallengeFrame implements Frame {
  final List<int> data; // 8 bytes

  PathChallengeFrame({required this.data}) {
    if (data.length != 8)
      throw ArgumentError('PATH_CHALLENGE data must be 8 bytes');
  }

  @override
  int get frameType => 0x1a;
  @override
  Uint8List serialize() => Uint8List.fromList([0x1a, ...data]);
}

// ---------------------------------------------------------------------------
// 0x1b PATH_RESPONSE
// ---------------------------------------------------------------------------
/// A PATH_RESPONSE frame (RFC 9000 Section 19.18).
class PathResponseFrame implements Frame {
  final List<int> data; // 8 bytes

  PathResponseFrame({required this.data}) {
    if (data.length != 8)
      throw ArgumentError('PATH_RESPONSE data must be 8 bytes');
  }

  @override
  int get frameType => 0x1b;
  @override
  Uint8List serialize() => Uint8List.fromList([0x1b, ...data]);
}

// ---------------------------------------------------------------------------
// 0x1c CONNECTION_CLOSE (transport)
// ---------------------------------------------------------------------------
/// A CONNECTION_CLOSE frame for transport errors (RFC 9000 Section 19.19).
class ConnectionCloseFrame implements Frame {
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
class ApplicationCloseFrame implements Frame {
  final int errorCode;
  final String reasonPhrase;

  ApplicationCloseFrame({required this.errorCode, this.reasonPhrase = ''});

  @override
  int get frameType => 0x1d;

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
class HandshakeDoneFrame implements Frame {
  HandshakeDoneFrame();
  @override
  int get frameType => 0x1e;
  @override
  Uint8List serialize() => Uint8List(1)..[0] = 0x1e;
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

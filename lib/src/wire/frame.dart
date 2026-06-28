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

class AckRange {
  final int gap;
  final int length;
  AckRange({this.gap = 0, required this.length});
}

// ---------------------------------------------------------------------------
// 0x03 ACK with ECN
// ---------------------------------------------------------------------------
class AckEcnFrame extends AckFrame {
  final int ect0Count;
  final int ect1Count;
  final int ceCount;

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
        final firstRangeLength = readVarInt(pos);
        pos += varIntLength(pos);
        final ranges = <AckRange>[];
        if (ackRangeCount > 0) {
          ranges.add(AckRange(gap: 0, length: firstRangeLength));
          for (var i = 1; i < ackRangeCount; i++) {
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
        final data = bytes.sublist(pos, pos + lengthValue);
        return CryptoFrame(offset: offsetValue, data: data);
      case 0x07: // NEW_TOKEN
        final lengthValue = readVarInt(pos);
        pos += varIntLength(pos);
        final token = bytes.sublist(pos, pos + lengthValue);
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
        } else {
          lengthValue = bytes.length - pos;
        }

        final data = bytes.sublist(pos, pos + lengthValue);
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
        final connectionId = bytes.sublist(pos, pos + connectionIdLength);
        pos += connectionIdLength;
        final statelessResetToken = bytes.sublist(pos, pos + 16);
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
        final data = bytes.sublist(pos, pos + 8);
        return PathChallengeFrame(data: data);
      case 0x1b: // PATH_RESPONSE
        final data = bytes.sublist(pos, pos + 8);
        return PathResponseFrame(data: data);
      case 0x1c: // CONNECTION_CLOSE (transport)
        final errorCode = readVarInt(pos);
        pos += varIntLength(pos);
        final offendingFrameType = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseLength = readVarInt(pos);
        pos += varIntLength(pos);
        final reasonPhraseBytes = bytes.sublist(pos, pos + reasonPhraseLength);
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
        final reasonPhraseBytes = bytes.sublist(pos, pos + reasonPhraseLength);
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

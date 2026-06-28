import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 frame types per RFC 9114 Section 7.2.
enum Http3FrameType {
  data(0x00),
  headers(0x01),
  cancelPush(0x03),
  settings(0x04),
  pushPromise(0x05),
  goaway(0x07),
  maxPushId(0x0d),
  reserved(0x21); // GREASE

  final int value;
  const Http3FrameType(this.value);

  /// Looks up a frame type by its wire value.
  static Http3FrameType? fromValue(int value) {
    for (final type in values) {
      if (type.value == value) return type;
    }
    return null;
  }
}

/// An HTTP/3 frame consisting of a type, length, and payload.
///
/// Wire format: VarInt(Type) + VarInt(Length) + Payload (Length bytes)
class Http3Frame {
  final Http3FrameType type;
  final List<int> payload;

  Http3Frame({required this.type, required this.payload});

  /// Serializes this frame into its on-the-wire representation.
  Uint8List serialize() {
    final typeBytes = VarInt.encode(type.value);
    final lengthBytes = VarInt.encode(payload.length);
    final result =
        Uint8List(typeBytes.length + lengthBytes.length + payload.length);
    result.setRange(0, typeBytes.length, typeBytes);
    result.setRange(
        typeBytes.length, typeBytes.length + lengthBytes.length, lengthBytes);
    result.setRange(
        typeBytes.length + lengthBytes.length, result.length, payload);
    return result;
  }

  /// Parses an HTTP/3 frame from [bytes] starting at [offset].
  ///
  /// Returns a record containing the parsed [Http3Frame] and the total number
  /// of bytes consumed.
  static (Http3Frame, int) parse(Uint8List bytes, {int offset = 0}) {
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'Offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    // Decode frame type
    final typeLength = VarInt.decodeLength(bytes[offset]);
    if (offset + typeLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $typeLength bytes for frame type at offset $offset',
      );
    }
    final typeValue = VarInt.decode(bytes.buffer, offset: offset);

    // Decode payload length
    final lengthOffset = offset + typeLength;
    if (lengthOffset >= bytes.length) {
      throw ArgumentError(
        'Buffer too short: missing frame length at offset $lengthOffset',
      );
    }
    final lengthLength = VarInt.decodeLength(bytes[lengthOffset]);
    if (lengthOffset + lengthLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $lengthLength bytes for frame length at offset $lengthOffset',
      );
    }
    final payloadLength = VarInt.decode(bytes.buffer, offset: lengthOffset);

    // Extract payload
    final payloadOffset = lengthOffset + lengthLength;
    if (payloadOffset + payloadLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $payloadLength bytes for frame payload at offset $payloadOffset, '
        'but buffer length is ${bytes.length}',
      );
    }
    final payload = bytes.sublist(payloadOffset, payloadOffset + payloadLength);

    final frameType = Http3FrameType.fromValue(typeValue);
    if (frameType == null) {
      throw ArgumentError(
        'Unknown frame type: 0x${typeValue.toRadixString(16)}',
      );
    }

    final totalLength = typeLength + lengthLength + payloadLength;
    return (Http3Frame(type: frameType, payload: payload), totalLength);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Http3Frame &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          _listsEqual(payload, other.payload);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(payload));

  static bool _listsEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

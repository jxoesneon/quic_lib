import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 PRIORITY_UPDATE frame payload (RFC 9218 Section 7).
///
/// Carries priority parameters for a request stream.
/// Wire format: VarInt(streamId) + priorityFieldValue_bytes.
class PriorityUpdateFrame {
  /// The request stream ID that this priority update applies to.
  final int streamId;

  /// The priority field value as an ASCII string (e.g., "u=3, i").
  final String priorityFieldValue;

  PriorityUpdateFrame({
    required this.streamId,
    required this.priorityFieldValue,
  });

  /// Serialize payload: VarInt(streamId) + priorityFieldValue_bytes.
  Uint8List serializePayload() {
    final streamIdBytes = VarInt.encode(streamId);
    final priorityBytes = ascii.encode(priorityFieldValue);
    final result = Uint8List(streamIdBytes.length + priorityBytes.length);
    result.setRange(0, streamIdBytes.length, streamIdBytes);
    result.setRange(streamIdBytes.length, result.length, priorityBytes);
    return result;
  }

  /// Alias for [serializePayload].
  Uint8List serialize() => serializePayload();

  /// Alias for [parsePayload].
  static PriorityUpdateFrame parse(Uint8List bytes) => parsePayload(bytes);

  /// Parse payload.
  static PriorityUpdateFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('PRIORITY_UPDATE payload cannot be empty');
    }
    final streamId = VarInt.decode(payload.buffer, offset: 0);
    final streamIdLength = VarInt.decodeLength(payload[0]);
    final priorityFieldValue =
        ascii.decode(payload.sublist(streamIdLength));
    return PriorityUpdateFrame(
      streamId: streamId,
      priorityFieldValue: priorityFieldValue,
    );
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.priorityUpdate,
      payload: serializePayload(),
    );
  }

  /// Returns the total on-the-wire byte length of the full HTTP/3 frame
  /// (type varint + length varint + payload).
  int getByteLength() {
    final payload = serializePayload();
    final typeBytes = VarInt.encode(Http3FrameType.priorityUpdate.value);
    final lengthBytes = VarInt.encode(payload.length);
    return typeBytes.length + lengthBytes.length + payload.length;
  }

  @override
  String toString() =>
      'PriorityUpdateFrame(streamId: $streamId, priority: "$priorityFieldValue")';

  @override
  bool operator ==(Object other) =>
      other is PriorityUpdateFrame &&
      other.streamId == streamId &&
      other.priorityFieldValue == priorityFieldValue;

  @override
  int get hashCode => Object.hash(streamId, priorityFieldValue);
}

/// HTTP/3 PRIORITY_UPDATE frame for push streams (RFC 9218 Section 7).
///
/// Same structure as [PriorityUpdateFrame], but the [streamId] field
/// semantically represents a Push ID, and the frame type is different.
class PriorityUpdatePushFrame {
  /// The push ID that this priority update applies to.
  final int streamId;

  /// The priority field value as an ASCII string (e.g., "u=3, i").
  final String priorityFieldValue;

  PriorityUpdatePushFrame({
    required this.streamId,
    required this.priorityFieldValue,
  });

  /// Serialize payload: VarInt(pushId) + priorityFieldValue_bytes.
  Uint8List serializePayload() {
    final streamIdBytes = VarInt.encode(streamId);
    final priorityBytes = ascii.encode(priorityFieldValue);
    final result = Uint8List(streamIdBytes.length + priorityBytes.length);
    result.setRange(0, streamIdBytes.length, streamIdBytes);
    result.setRange(streamIdBytes.length, result.length, priorityBytes);
    return result;
  }

  /// Alias for [serializePayload].
  Uint8List serialize() => serializePayload();

  /// Alias for [parsePayload].
  static PriorityUpdatePushFrame parse(Uint8List bytes) => parsePayload(bytes);

  /// Parse payload.
  static PriorityUpdatePushFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('PRIORITY_UPDATE_PUSH payload cannot be empty');
    }
    final streamId = VarInt.decode(payload.buffer, offset: 0);
    final streamIdLength = VarInt.decodeLength(payload[0]);
    final priorityFieldValue =
        ascii.decode(payload.sublist(streamIdLength));
    return PriorityUpdatePushFrame(
      streamId: streamId,
      priorityFieldValue: priorityFieldValue,
    );
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.priorityUpdatePush,
      payload: serializePayload(),
    );
  }

  /// Returns the total on-the-wire byte length of the full HTTP/3 frame
  /// (type varint + length varint + payload).
  int getByteLength() {
    final payload = serializePayload();
    final typeBytes = VarInt.encode(Http3FrameType.priorityUpdatePush.value);
    final lengthBytes = VarInt.encode(payload.length);
    return typeBytes.length + lengthBytes.length + payload.length;
  }

  @override
  String toString() =>
      'PriorityUpdatePushFrame(pushId: $streamId, priority: "$priorityFieldValue")';

  @override
  bool operator ==(Object other) =>
      other is PriorityUpdatePushFrame &&
      other.streamId == streamId &&
      other.priorityFieldValue == priorityFieldValue;

  @override
  int get hashCode => Object.hash(streamId, priorityFieldValue);
}

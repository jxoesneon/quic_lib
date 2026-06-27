import 'dart:typed_data';

import 'package:dart_quic/src/webtransport/capsule_types.dart';
import 'package:dart_quic/src/wire/varint.dart';

/// A WebTransport capsule that registers a stream for a session.
class StreamCapsule {
  final int streamId;
  final CapsuleType type;

  StreamCapsule({
    required this.streamId,
    required this.type,
  });

  /// Serialize to bytes: VarInt(type) + VarInt(streamId)
  Uint8List serialize() {
    final typeBytes = VarInt.encode(type.value);
    final streamIdBytes = VarInt.encode(streamId);
    final result = Uint8List(typeBytes.length + streamIdBytes.length);
    result.setRange(0, typeBytes.length, typeBytes);
    result.setRange(typeBytes.length, result.length, streamIdBytes);
    return result;
  }

  /// Parse from bytes.
  static StreamCapsule parse(Uint8List bytes) {
    final typeValue = VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes);
    final typeLen = VarInt.decodeLength(bytes[0]);
    final streamId = VarInt.decode(
      bytes.buffer,
      offset: bytes.offsetInBytes + typeLen,
    );
    final type = CapsuleType.fromValue(typeValue)!;
    return StreamCapsule(streamId: streamId, type: type);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is StreamCapsule &&
          runtimeType == other.runtimeType &&
          streamId == other.streamId &&
          type == other.type;

  @override
  int get hashCode => Object.hash(streamId, type);

  @override
  String toString() => 'StreamCapsule(streamId: $streamId, type: $type)';
}

/// Registry for [StreamCapsule] entries, used for bidirectional stream tracking.
class StreamCapsuleRegistry {
  final Map<int, StreamCapsule> _capsules = {};

  /// Register a capsule for the given [streamId].
  void register(int streamId, Capsule capsule) {
    _capsules[streamId] = StreamCapsule(streamId: streamId, type: capsule.type);
  }

  /// Retrieve a registered capsule by [streamId].
  StreamCapsule? get(int streamId) => _capsules[streamId];

  /// Whether a capsule is registered for [streamId].
  bool isRegistered(int streamId) => _capsules.containsKey(streamId);
}

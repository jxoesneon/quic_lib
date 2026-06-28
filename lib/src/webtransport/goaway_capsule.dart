import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';

/// A WebTransport GOAWAY capsule (draft-ietf-webtrans-http3).
///
/// Signals that the sender will not initiate any new WebTransport sessions
/// on the current connection, and optionally specifies the last stream ID
/// that will be accepted.
class GoawayCapsule {
  final int? streamId;

  GoawayCapsule({this.streamId});

  /// Serialize to bytes: VarInt(type) + optional VarInt(streamId).
  ///
  /// The type is 0x1d (goaway).
  Uint8List serialize() {
    final typeBytes = VarInt.encode(0x1d);
    if (streamId != null) {
      final streamIdBytes = VarInt.encode(streamId!);
      final result = Uint8List(typeBytes.length + streamIdBytes.length);
      result.setRange(0, typeBytes.length, typeBytes);
      result.setRange(typeBytes.length, result.length, streamIdBytes);
      return result;
    }
    return typeBytes;
  }

  /// Parse from bytes, skipping the leading type varint.
  static GoawayCapsule parse(Uint8List bytes) {
    final typeLen = VarInt.decodeLength(bytes[0]);
    if (bytes.length == typeLen) {
      return GoawayCapsule();
    }
    final streamId = VarInt.decode(
      bytes.buffer,
      offset: bytes.offsetInBytes + typeLen,
    );
    return GoawayCapsule(streamId: streamId);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GoawayCapsule &&
          runtimeType == other.runtimeType &&
          streamId == other.streamId;

  @override
  int get hashCode => streamId.hashCode;

  @override
  String toString() => 'GoawayCapsule(streamId: $streamId)';
}

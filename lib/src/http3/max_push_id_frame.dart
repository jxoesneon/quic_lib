import 'dart:typed_data';

import 'package:dart_quic/src/http3/frame_types.dart';
import 'package:dart_quic/src/wire/varint.dart';

/// HTTP/3 MAX_PUSH_ID frame payload.
///
/// RFC 9114 Section 7.2.7: the payload consists of a single VarInt
/// identifying the maximum Push ID the server can use in a server push.
class Http3MaxPushIdFrame {
  /// The maximum Push ID.
  final int pushId;

  Http3MaxPushIdFrame({required this.pushId});

  /// Serialize payload: VarInt(pushId)
  Uint8List serializePayload() {
    return VarInt.encode(pushId);
  }

  /// Parse payload.
  static Http3MaxPushIdFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('MAX_PUSH_ID payload cannot be empty');
    }
    final value = VarInt.decode(payload.buffer, offset: 0);
    return Http3MaxPushIdFrame(pushId: value);
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.maxPushId,
      payload: serializePayload(),
    );
  }

  @override
  String toString() => 'Http3MaxPushIdFrame(pushId: $pushId)';

  @override
  bool operator ==(Object other) =>
      other is Http3MaxPushIdFrame && other.pushId == pushId;

  @override
  int get hashCode => pushId.hashCode;
}

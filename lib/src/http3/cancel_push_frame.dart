import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 CANCEL_PUSH frame payload.
///
/// RFC 9114 Section 7.2.3: the payload consists of a single VarInt
/// identifying the Push ID that the sender wishes to cancel.
class Http3CancelPushFrame {
  /// The Push ID to cancel.
  final int pushId;

  Http3CancelPushFrame({required this.pushId});

  /// Serialize payload: VarInt(pushId)
  Uint8List serializePayload() {
    return VarInt.encode(pushId);
  }

  /// Alias for [serializePayload].
  Uint8List serialize() => serializePayload();

  /// Alias for [parsePayload].
  static Http3CancelPushFrame parse(Uint8List bytes) => parsePayload(bytes);

  /// Parse payload.
  static Http3CancelPushFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('CANCEL_PUSH payload cannot be empty');
    }
    final value = VarInt.decode(payload.buffer, offset: 0);
    return Http3CancelPushFrame(pushId: value);
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.cancelPush,
      payload: serializePayload(),
    );
  }

  @override
  String toString() => 'Http3CancelPushFrame(pushId: $pushId)';

  @override
  bool operator ==(Object other) =>
      other is Http3CancelPushFrame && other.pushId == pushId;

  @override
  int get hashCode => pushId.hashCode;
}

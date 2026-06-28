import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 GOAWAY frame payload.
///
/// RFC 9114 Section 7.2.6: the payload consists of a single VarInt
/// identifying either the last client-initiated bidirectional stream ID
/// the server will accept, or (on servers) a push ID.
class Http3GoawayFrame {
  /// The last stream ID the server will accept.
  /// For client: bidirectional stream ID (client-initiated).
  /// For server: push ID.
  final int lastStreamIdOrPushId;

  Http3GoawayFrame({required this.lastStreamIdOrPushId});

  /// Serialize payload: VarInt(lastStreamIdOrPushId)
  Uint8List serializePayload() {
    return VarInt.encode(lastStreamIdOrPushId);
  }

  /// Parse payload.
  static Http3GoawayFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('GOAWAY payload cannot be empty');
    }
    final value = VarInt.decode(payload.buffer, offset: 0);
    return Http3GoawayFrame(lastStreamIdOrPushId: value);
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.goaway,
      payload: serializePayload(),
    );
  }

  @override
  String toString() =>
      'Http3GoawayFrame(lastStreamIdOrPushId: $lastStreamIdOrPushId)';

  @override
  bool operator ==(Object other) =>
      other is Http3GoawayFrame &&
      other.lastStreamIdOrPushId == lastStreamIdOrPushId;

  @override
  int get hashCode => lastStreamIdOrPushId.hashCode;
}

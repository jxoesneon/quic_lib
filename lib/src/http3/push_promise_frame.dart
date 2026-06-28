import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 PUSH_PROMISE frame payload.
///
/// RFC 9114 Section 7.2.5: the payload consists of a VarInt-encoded Push ID
/// followed by an encoded field section (QPACK-encoded request headers).
class Http3PushPromiseFrame {
  /// The Push ID that the server is reserving for this server push.
  final int pushId;

  /// The encoded field section, i.e., a QPACK-encoded header block.
  final List<int> encodedFieldSection;

  Http3PushPromiseFrame({
    required this.pushId,
    required this.encodedFieldSection,
  });

  /// Serialize payload: VarInt(pushId) + encodedFieldSection
  Uint8List serializePayload() {
    final pushIdBytes = VarInt.encode(pushId);
    final result = Uint8List(pushIdBytes.length + encodedFieldSection.length);
    result.setRange(0, pushIdBytes.length, pushIdBytes);
    result.setRange(pushIdBytes.length, result.length, encodedFieldSection);
    return result;
  }

  /// Alias for [serializePayload].
  Uint8List serialize() => serializePayload();

  /// Alias for [parsePayload].
  static Http3PushPromiseFrame parse(Uint8List bytes) => parsePayload(bytes);

  /// Parse payload.
  static Http3PushPromiseFrame parsePayload(Uint8List payload) {
    if (payload.isEmpty) {
      throw ArgumentError('PUSH_PROMISE payload cannot be empty');
    }
    final pushId = VarInt.decode(payload.buffer, offset: 0);
    final pushIdLength = VarInt.decodeLength(payload[0]);
    final encodedFieldSection = payload.sublist(pushIdLength);
    return Http3PushPromiseFrame(
      pushId: pushId,
      encodedFieldSection: encodedFieldSection,
    );
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.pushPromise,
      payload: serializePayload(),
    );
  }

  @override
  String toString() =>
      'Http3PushPromiseFrame(pushId: $pushId, encodedFieldSection: ${encodedFieldSection.length} bytes)';

  @override
  bool operator ==(Object other) =>
      other is Http3PushPromiseFrame &&
      other.pushId == pushId &&
      _listsEqual(other.encodedFieldSection, encodedFieldSection);

  @override
  int get hashCode => Object.hash(pushId, Object.hashAll(encodedFieldSection));

  static bool _listsEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

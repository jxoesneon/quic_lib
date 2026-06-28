import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/utils/collections.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 ORIGIN frame payload.
///
/// RFC 9412 Section 2.2: the payload consists of zero or more
/// origin entries. Each entry is a VarInt-encoded length followed by
/// an ASCII-encoded origin (scheme + host + port, e.g.,
/// "https://example.com").
class OriginFrame {
  /// The alternative origins advertised by this frame.
  final List<String> origins;

  OriginFrame({required this.origins});

  /// Serialize payload: sequence of VarInt(length) + origin_bytes.
  Uint8List serializePayload() {
    final builder = BytesBuilder();
    for (final origin in origins) {
      final originBytes = utf8.encode(origin);
      builder.add(VarInt.encode(originBytes.length));
      builder.add(originBytes);
    }
    return builder.toBytes();
  }

  /// Alias for [serializePayload].
  Uint8List serialize() => serializePayload();

  /// Alias for [parsePayload].
  static OriginFrame parse(Uint8List bytes) => parsePayload(bytes);

  /// Parse payload.
  static OriginFrame parsePayload(Uint8List payload) {
    final parsedOrigins = <String>[];
    var offset = 0;

    while (offset < payload.length) {
      final length = VarInt.decode(payload.buffer, offset: offset);
      final lengthLength = VarInt.decodeLength(payload[offset]);
      offset += lengthLength;

      if (offset + length > payload.length) {
        throw ArgumentError(
          'ORIGIN payload too short: expected $length bytes at offset $offset',
        );
      }

      final originBytes = payload.sublist(offset, offset + length);
      parsedOrigins.add(utf8.decode(originBytes));
      offset += length;
    }

    return OriginFrame(origins: parsedOrigins);
  }

  /// Build a complete frame.
  Http3Frame toFrame() {
    return Http3Frame(
      type: Http3FrameType.origin,
      payload: serializePayload(),
    );
  }

  /// Returns the total on-the-wire byte length of the full HTTP/3 frame
  /// (type varint + length varint + payload).
  int getByteLength() {
    final payload = serializePayload();
    final typeBytes = VarInt.encode(Http3FrameType.origin.value);
    final lengthBytes = VarInt.encode(payload.length);
    return typeBytes.length + lengthBytes.length + payload.length;
  }

  @override
  String toString() => 'OriginFrame(origins: $origins)';

  @override
  bool operator ==(Object other) =>
      other is OriginFrame && listEquals(other.origins, origins);

  @override
  int get hashCode => Object.hashAll(origins);
}

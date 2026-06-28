import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/http3/frame_types.dart';
import 'package:quic_lib/src/utils/collections.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// HTTP/3 ORIGIN frame payload.
///
/// RFC 9412 Section 2.1: the payload consists of zero or more
/// origin entries. Each entry is a 16-bit unsigned integer
/// (Origin-Len) in network byte order, followed by an ASCII-encoded
/// origin (scheme + host + port, e.g., "https://example.com").
class OriginFrame {
  /// The alternative origins advertised by this frame.
  final List<String> origins;

  OriginFrame({required this.origins});

  /// Serialize payload: sequence of 16-bit uint(length) + origin_bytes.
  Uint8List serializePayload() {
    final builder = BytesBuilder();
    for (final origin in origins) {
      final originBytes = utf8.encode(origin);
      if (originBytes.length > 65535) {
        throw ArgumentError('Origin too long: ${originBytes.length} bytes');
      }
      builder.addByte((originBytes.length >> 8) & 0xFF);
      builder.addByte(originBytes.length & 0xFF);
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
      if (offset + 2 > payload.length) {
        throw ArgumentError(
          'ORIGIN payload too short for Origin-Len at offset $offset',
        );
      }
      final length = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;

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

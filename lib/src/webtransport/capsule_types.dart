import 'dart:typed_data';

import 'package:quic_lib/src/utils/collections.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Capsule types for WebTransport over HTTP/3 (RFC 9220).
enum CapsuleType {
  /// Unreliable datagram capsule.
  datagram(0x00),

  /// Close WebTransport session capsule.
  closeWebTransportSession(0x2843),

  /// Drain WebTransport session capsule.
  drainWebTransportSession(0x78ae),

  /// Register a bidirectional stream capsule.
  registerBidirectionalStream(0x41),

  /// Register a unidirectional stream capsule.
  registerUnidirectionalStream(0x42),

  /// GOAWAY capsule.
  goaway(0x1d),

  /// Session-level flow-control limit capsule (RFC 9220 §3).
  ///
  /// Payload is a single varint encoding the maximum number of bytes the
  /// receiver is willing to accept on the session as a whole. Receiving this
  /// capsule updates the sender's session-level send credit.
  webtransportMaxData(0x2c),

  /// Stream-level flow-control limit capsule (RFC 9220 §3).
  ///
  /// Payload is `VarInt(streamId) + VarInt(maxData)`, advertising the maximum
  /// number of bytes the receiver is willing to accept on the named stream.
  webtransportMaxStreamData(0x2d),

  /// Drain-capabilities capsule (RFC 9220 §3).
  ///
  /// Sent by a receiver that wants to reduce the sender's session-level credit.
  /// The payload is a single varint encoding the new (lower) session credit
  /// limit the sender must not exceed.
  drainCapabilities(0x2b),

  // Extension capsules (GREASE)
  /// Reserved GREASE capsule type.
  grease0(0x1b),

  /// Reserved GREASE capsule type.
  grease1(0x2a);

  /// Wire value of the capsule type.
  final int value;
  const CapsuleType(this.value);

  /// Looks up a capsule type by its wire [value].
  static CapsuleType? fromValue(int value) {
    for (final type in values) {
      if (type.value == value) {
        return type;
      }
    }
    return null;
  }
}

/// A WebTransport capsule consisting of a type, length, and payload.
///
/// This class is distinct from the HTTP/3 `Capsule` class in
/// `lib/src/http3/capsule_protocol.dart`. The two classes previously shared a
/// name and were both exported from `quic_lib.dart`, causing a public API
/// ambiguity. The WebTransport class is now named `WebTransportCapsule`.
class WebTransportCapsule {
  /// Capsule type.
  final CapsuleType type;

  /// Capsule payload bytes.
  final List<int> payload;

  /// Creates a WebTransport capsule of [type] carrying [payload].
  WebTransportCapsule({required this.type, required this.payload});

  /// Serialize: VarInt(type) + VarInt(length) + payload
  Uint8List serialize() {
    final typeBytes = VarInt.encode(type.value);
    final lengthBytes = VarInt.encode(payload.length);
    final result = Uint8List(
      typeBytes.length + lengthBytes.length + payload.length,
    );
    result.setRange(0, typeBytes.length, typeBytes);
    result.setRange(
      typeBytes.length,
      typeBytes.length + lengthBytes.length,
      lengthBytes,
    );
    result.setRange(
        typeBytes.length + lengthBytes.length, result.length, payload);
    return result;
  }

  /// Parse from bytes.
  ///
  /// Returns the parsed [WebTransportCapsule] and the number of bytes consumed.
  static (WebTransportCapsule, int) parse(Uint8List bytes, {int offset = 0}) {
    if (offset < 0 || offset > bytes.length) {
      throw ArgumentError('Offset $offset out of bounds');
    }

    final baseOffset = bytes.offsetInBytes + offset;
    final buffer = bytes.buffer;

    // Read type varint
    final typeValue = VarInt.decode(buffer, offset: baseOffset);
    final typeByteLength = VarInt.decodeLength(bytes[offset]);

    // Read length varint
    final lengthValue = VarInt.decode(
      buffer,
      offset: baseOffset + typeByteLength,
    );
    final lengthByteLength =
        VarInt.decodeLength(bytes[offset + typeByteLength]);

    final headerLength = typeByteLength + lengthByteLength;
    final totalLength = headerLength + lengthValue;

    if (offset + totalLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $totalLength bytes starting at offset '
        '$offset, but buffer length is ${bytes.length}',
      );
    }

    final type = CapsuleType.fromValue(typeValue);
    if (type == null) {
      throw ArgumentError(
        'Unknown capsule type: 0x${typeValue.toRadixString(16)}',
      );
    }

    final payloadOffset = offset + headerLength;
    final payload = Uint8List.sublistView(
      bytes,
      payloadOffset,
      payloadOffset + lengthValue,
    );

    return (WebTransportCapsule(type: type, payload: payload), totalLength);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is WebTransportCapsule &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          listEquals(payload, other.payload);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(payload));

  @override
  String toString() =>
      'WebTransportCapsule(type: ${type.name}, payload: ${payload.length} bytes)';
}

/// Deprecated alias for [WebTransportCapsule].
///
/// The old name collided with the HTTP/3 `Capsule` class in
/// `lib/src/http3/capsule_protocol.dart`. Use [WebTransportCapsule] instead;
/// this alias will be removed in a future major release.
@Deprecated('Use WebTransportCapsule instead.')
typedef Capsule = WebTransportCapsule;

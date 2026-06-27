import 'dart:typed_data';

import 'package:dart_quic/src/wire/varint.dart';

/// Capsule types for WebTransport over HTTP/3 (RFC 9220).
enum CapsuleType {
  closeWebTransportSession(0x1a4),
  drainWebTransportSession(0x78ae),
  // Extension capsules (GREASE)
  grease0(0x1b),
  grease1(0x2a);

  final int value;
  const CapsuleType(this.value);

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
class Capsule {
  final CapsuleType type;
  final List<int> payload;

  Capsule({required this.type, required this.payload});

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
    result.setRange(typeBytes.length + lengthBytes.length, result.length, payload);
    return result;
  }

  /// Parse from bytes.
  ///
  /// Returns the parsed [Capsule] and the number of bytes consumed.
  static (Capsule, int) parse(Uint8List bytes, {int offset = 0}) {
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
    final lengthByteLength = VarInt.decodeLength(bytes[offset + typeByteLength]);

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

    return (Capsule(type: type, payload: payload), totalLength);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Capsule &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          _listEquals(payload, other.payload);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(payload));

  @override
  String toString() =>
      'Capsule(type: ${type.name}, payload: ${payload.length} bytes)';
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

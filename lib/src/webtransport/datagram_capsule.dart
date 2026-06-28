import 'dart:typed_data';

import 'package:quic_lib/src/wire/varint.dart';

/// A WebTransport datagram capsule (RFC 9220 Section 5.1).
///
/// Datagram capsules have type 0x00 and carry an opaque payload.
class DatagramCapsule {
  final Uint8List payload;

  DatagramCapsule(this.payload);

  /// Serialize to bytes: VarInt(type) + payload.
  ///
  /// The type is 0x00 (datagram).
  Uint8List serialize() {
    final typeBytes = VarInt.encode(0x00);
    final result = Uint8List(typeBytes.length + payload.length);
    result.setRange(0, typeBytes.length, typeBytes);
    result.setRange(typeBytes.length, result.length, payload);
    return result;
  }

  /// Parse from bytes, skipping the leading type varint.
  static DatagramCapsule parse(Uint8List bytes) {
    final typeByteLength = VarInt.decodeLength(bytes[0]);
    final payload = Uint8List.sublistView(bytes, typeByteLength);
    return DatagramCapsule(payload);
  }
}

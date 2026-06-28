import 'dart:typed_data';

import 'package:quic_lib/src/utils/collections.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Base class for the Capsule Protocol (RFC 9297).
///
/// Each capsule on the wire is:
///   VarInt(Type) + VarInt(Length) + Data (Length bytes)
abstract class Capsule {
  final int type;
  final Uint8List data;

  Capsule({required this.type, required this.data});

  /// Serializes this capsule into its on-the-wire representation.
  Uint8List serialize() {
    final typeBytes = VarInt.encode(type);
    final lengthBytes = VarInt.encode(data.length);
    final result =
        Uint8List(typeBytes.length + lengthBytes.length + data.length);
    result.setRange(0, typeBytes.length, typeBytes);
    result.setRange(
        typeBytes.length, typeBytes.length + lengthBytes.length, lengthBytes);
    result.setRange(
        typeBytes.length + lengthBytes.length, result.length, data);
    return result;
  }

  /// Parses a capsule from [bytes] starting at [offset].
  ///
  /// Returns a record containing the parsed [Capsule] and the total number of
  /// bytes consumed.
  static (Capsule, int) parse(Uint8List bytes, {int offset = 0}) {
    if (offset < 0 || offset >= bytes.length) {
      throw ArgumentError(
        'Offset $offset out of bounds for buffer of length ${bytes.length}',
      );
    }

    // Decode capsule type
    final typeLength = VarInt.decodeLength(bytes[offset]);
    if (offset + typeLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $typeLength bytes for capsule type',
      );
    }
    final type = VarInt.decode(bytes.buffer, offset: offset);

    // Decode data length
    final lengthOffset = offset + typeLength;
    if (lengthOffset >= bytes.length) {
      throw ArgumentError(
        'Buffer too short: missing capsule length at offset $lengthOffset',
      );
    }
    final lengthLength = VarInt.decodeLength(bytes[lengthOffset]);
    if (lengthOffset + lengthLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $lengthLength bytes for capsule length',
      );
    }
    final dataLength = VarInt.decode(bytes.buffer, offset: lengthOffset);

    // Extract data
    final dataOffset = lengthOffset + lengthLength;
    if (dataOffset + dataLength > bytes.length) {
      throw ArgumentError(
        'Buffer too short: need $dataLength bytes for capsule data at offset '
        '$dataOffset, but buffer length is ${bytes.length}',
      );
    }
    final data = bytes.sublist(dataOffset, dataOffset + dataLength);

    final totalLength = typeLength + lengthLength + dataLength;

    final capsule = _createCapsule(type, data);
    return (capsule, totalLength);
  }

  static Capsule _createCapsule(int type, Uint8List data) {
    switch (type) {
      case 0x00:
        return DatagramCapsule(data);
      case 0x1a4:
        return CloseWebTransportSessionCapsule(data);
      case 0x78ae:
        return DrainWebTransportSessionCapsule(data);
      case 0x41:
        return RegisterBidirectionalStreamCapsule(data);
      case 0x42:
        return RegisterUnidirectionalStreamCapsule(data);
      case 0x1d:
        return GoawayCapsule(data);
      default:
        throw ArgumentError(
          'Unknown capsule type: 0x${type.toRadixString(16)}',
        );
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Capsule &&
          runtimeType == other.runtimeType &&
          type == other.type &&
          listEquals(data, other.data);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(data));
}

/// A DATAGRAM capsule (type 0x00) carrying unreliable datagram data.
class DatagramCapsule extends Capsule {
  DatagramCapsule(Uint8List data) : super(type: 0x00, data: data);
}

/// A CLOSE_WEBTRANSPORT_SESSION capsule (type 0x1a4).
class CloseWebTransportSessionCapsule extends Capsule {
  CloseWebTransportSessionCapsule(Uint8List data)
      : super(type: 0x1a4, data: data);
}

/// A DRAIN_WEBTRANSPORT_SESSION capsule (type 0x78ae).
class DrainWebTransportSessionCapsule extends Capsule {
  DrainWebTransportSessionCapsule(Uint8List data)
      : super(type: 0x78ae, data: data);
}

/// A REGISTER_BIDIRECTIONAL_STREAM capsule (type 0x41).
class RegisterBidirectionalStreamCapsule extends Capsule {
  RegisterBidirectionalStreamCapsule(Uint8List data)
      : super(type: 0x41, data: data);
}

/// A REGISTER_UNIDIRECTIONAL_STREAM capsule (type 0x42).
class RegisterUnidirectionalStreamCapsule extends Capsule {
  RegisterUnidirectionalStreamCapsule(Uint8List data)
      : super(type: 0x42, data: data);
}

/// A GOAWAY capsule (type 0x1d).
class GoawayCapsule extends Capsule {
  GoawayCapsule(Uint8List data) : super(type: 0x1d, data: data);
}

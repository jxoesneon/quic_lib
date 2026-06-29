import 'dart:convert';
import 'dart:typed_data';

import 'package:quic_lib/src/utils/collections.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// This file implements the capsule types defined by RFC 9220 and
/// WebTransport over HTTP/3:
/// DATAGRAM (0x00), CLOSE_WEBTRANSPORT_SESSION (0x2843),
/// DRAIN_WEBTRANSPORT_SESSION (0x78ae), GOAWAY (0x1d),
/// REGISTER_BIDIRECTIONAL_STREAM (0x41),
/// REGISTER_UNIDIRECTIONAL_STREAM (0x42),
/// WT_MAX_STREAMS (0x190B4D3F/0x190B4D40), WT_MAX_DATA, and
/// WT_MAX_STREAM_DATA (draft-ietf-webtrans-http3).

/// Maximum size of a capsule payload accepted by the parser (1 MiB).
///
/// Limits memory allocation when receiving unknown or malicious capsules.
const int _maxCapsuleDataLength = 1024 * 1024;

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
    result.setRange(typeBytes.length + lengthBytes.length, result.length, data);
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
    if (dataLength > _maxCapsuleDataLength) {
      throw ArgumentError(
        'Capsule data length $dataLength exceeds maximum allowed '
        '$_maxCapsuleDataLength bytes',
      );
    }

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
      case 0x2843:
        return CloseWebTransportSessionCapsule(data: data);
      case 0x78ae:
        return DrainWebTransportSessionCapsule(data);
      case 0x1d:
        return GoawayCapsule(data);
      case 0x41:
        return RegisterBidirectionalStreamCapsule(data);
      case 0x42:
        return RegisterUnidirectionalStreamCapsule(data);
      case 0x190B4D3F:
        return WtMaxStreamsCapsule.bidi(data);
      case 0x190B4D40:
        return WtMaxStreamsCapsule.uni(data);
      case 0x190B4D41:
        return WtMaxDataCapsule(data);
      case 0x190B4D42:
        return WtMaxStreamDataCapsule(data);
      default:
        // Unknown capsule types are ignored per draft-ietf-webtrans-http3.
        return UnknownCapsule(type, data);
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

/// A CLOSE_WEBTRANSPORT_SESSION capsule (type 0x2843).
class CloseWebTransportSessionCapsule extends Capsule {
  final int errorCode;
  final String? errorMessage;

  CloseWebTransportSessionCapsule({
    Uint8List? data,
    int errorCode = 0,
    String? errorMessage,
  })  : errorCode = (data != null) ? _decodeErrorCode(data) : errorCode,
        errorMessage =
            (data != null) ? _decodeErrorMessage(data) : errorMessage,
        super(
          type: 0x2843,
          data: data ?? _buildData(errorCode, errorMessage),
        );

  static Uint8List _buildData(int errorCode, String? errorMessage) {
    final builder = BytesBuilder();
    final byteData = ByteData(4);
    byteData.setUint32(0, errorCode, Endian.big);
    builder.add(byteData.buffer.asUint8List());
    if (errorMessage != null && errorMessage.isNotEmpty) {
      final msgBytes = Uint8List.fromList(utf8.encode(errorMessage));
      builder.add(VarInt.encode(msgBytes.length));
      builder.add(msgBytes);
    }
    return builder.toBytes();
  }

  static int _decodeErrorCode(Uint8List data) {
    if (data.length >= 4) {
      return ByteData.sublistView(data).getUint32(0, Endian.big);
    }
    return 0;
  }

  static String? _decodeErrorMessage(Uint8List data) {
    if (data.length > 4) {
      final length = VarInt.decode(data.buffer, offset: data.offsetInBytes + 4);
      final lengthBytes = VarInt.decodeLength(data[4]);
      final msgBytes = data.sublist(4 + lengthBytes, 4 + lengthBytes + length);
      return utf8.decode(msgBytes);
    }
    return null;
  }
}

/// A DRAIN_WEBTRANSPORT_SESSION capsule (type 0x78ae).
class DrainWebTransportSessionCapsule extends Capsule {
  DrainWebTransportSessionCapsule(Uint8List data)
      : super(type: 0x78ae, data: data);
}

/// A GOAWAY capsule (type 0x1d).
class GoawayCapsule extends Capsule {
  GoawayCapsule(Uint8List data) : super(type: 0x1d, data: data);
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

/// An unknown capsule type encountered on the wire.
///
/// Per draft-ietf-webtrans-http3, unknown capsule types MUST be ignored.
class UnknownCapsule extends Capsule {
  UnknownCapsule(int type, Uint8List data) : super(type: type, data: data);
}

/// WT_MAX_STREAMS capsule (draft-ietf-webtrans-http3 §5.6.2).
///
/// Carries a VarInt count of maximum streams allowed for a session.
class WtMaxStreamsCapsule extends Capsule {
  final bool bidirectional;

  WtMaxStreamsCapsule.bidi(Uint8List data)
      : bidirectional = true,
        super(type: 0x190B4D3F, data: data);

  WtMaxStreamsCapsule.uni(Uint8List data)
      : bidirectional = false,
        super(type: 0x190B4D40, data: data);

  /// Maximum streams value encoded in the capsule payload.
  int get maxStreams => VarInt.decode(data.buffer, offset: data.offsetInBytes);
}

/// WT_MAX_DATA capsule (draft-ietf-webtrans-http3 §5.6.3).
///
/// Carries a VarInt count of maximum bytes allowed for a session.
class WtMaxDataCapsule extends Capsule {
  WtMaxDataCapsule(Uint8List data) : super(type: 0x190B4D41, data: data);

  /// Maximum data value encoded in the capsule payload.
  int get maxData => VarInt.decode(data.buffer, offset: data.offsetInBytes);
}

/// WT_MAX_STREAM_DATA capsule (draft-ietf-webtrans-http3 §5.6.4).
///
/// Carries a VarInt count of maximum bytes allowed on a stream.
class WtMaxStreamDataCapsule extends Capsule {
  WtMaxStreamDataCapsule(Uint8List data) : super(type: 0x190B4D42, data: data);

  /// Maximum stream data value encoded in the capsule payload.
  int get maxStreamData => VarInt.decode(data.buffer, offset: data.offsetInBytes);
}

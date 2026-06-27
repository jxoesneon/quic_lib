import 'dart:typed_data';

/// A simplified DCUtR message scaffold.
///
/// Serialize format: uint8 type + uint16 addr_length (big-endian) + addr_bytes
class DCUtRMessage {
  static const int typeConnect = 0x01;
  static const int typeSync = 0x02;

  final int type;
  final List<int> observedAddr;

  DCUtRMessage({required this.type, required this.observedAddr});

  /// Serialize to bytes: uint8 type + uint16 addr_length + addr_bytes.
  Uint8List serialize() {
    final addrBytes = Uint8List.fromList(observedAddr);
    final length = addrBytes.length;
    if (length > 0xFFFF) {
      throw ArgumentError('observedAddr length exceeds uint16 max');
    }
    final result = Uint8List(1 + 2 + length);
    final view = ByteData.view(result.buffer);
    view.setUint8(0, type);
    view.setUint16(1, length, Endian.big);
    result.setAll(3, addrBytes);
    return result;
  }

  /// Parse from bytes.
  static DCUtRMessage parse(Uint8List bytes) {
    if (bytes.length < 3) {
      throw FormatException('DCUtR message too short');
    }
    final view = ByteData.view(
      bytes.buffer,
      bytes.offsetInBytes,
      bytes.length,
    );
    final type = view.getUint8(0);
    final length = view.getUint16(1, Endian.big);
    if (bytes.length < 3 + length) {
      throw FormatException('DCUtR message truncated');
    }
    final addrBytes = bytes.sublist(3, 3 + length);
    return DCUtRMessage(type: type, observedAddr: addrBytes);
  }

  @override
  bool operator ==(Object other) =>
      other is DCUtRMessage &&
      other.type == type &&
      _listEquals(other.observedAddr, observedAddr);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(observedAddr));

  static bool _listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Handler for producing and validating DCUtR messages.
class DCUtRHandler {
  static const int typeConnect = DCUtRMessage.typeConnect;
  static const int typeSync = DCUtRMessage.typeSync;

  /// Initiate a DCUtR handshake as the dialer.
  DCUtRMessage initiateConnect(List<int> observedAddr) {
    return DCUtRMessage(type: typeConnect, observedAddr: observedAddr);
  }

  /// Respond to a DCUtR CONNECT with a SYNC.
  DCUtRMessage respondSync(List<int> observedAddr) {
    return DCUtRMessage(type: typeSync, observedAddr: observedAddr);
  }

  /// Validate a received DCUtR message.
  bool isValid(DCUtRMessage msg) {
    return msg.type == typeConnect || msg.type == typeSync;
  }
}

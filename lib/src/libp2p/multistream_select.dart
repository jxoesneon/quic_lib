import 'dart:convert';
import 'dart:typed_data';

import '../wire/varint.dart';

/// libp2p multistream-select / protocol negotiation.
class MultistreamSelect {
  static const String protocolId = '/multistream/1.0.0';
  static const String newline = '\n';

  /// The multistream header: `<protocolId>\n` as UTF-8 bytes.
  static Uint8List get header => Uint8List.fromList(utf8.encode('$protocolId\n'));

  /// Encode a protocol list: `<protocol>\n` for each.
  static Uint8List encodeProtocols(List<String> protocols) {
    final buffer = BytesBuilder();
    for (final p in protocols) {
      buffer.add(utf8.encode('$p\n'));
    }
    return buffer.toBytes();
  }

  /// Encode a single protocol selection.
  static Uint8List encodeProtocol(String protocol) {
    return Uint8List.fromList(utf8.encode('$protocol\n'));
  }

  /// Encode the NA (not available) response.
  static Uint8List get na => Uint8List.fromList(utf8.encode('na\n'));

  /// Encode the `ls` command.
  static Uint8List get ls => Uint8List.fromList(utf8.encode('ls\n'));

  /// Parse incoming multistream-select messages.
  static List<String> parseMessages(Uint8List bytes) {
    final text = utf8.decode(bytes);
    return text.split(newline).where((s) => s.isNotEmpty).toList();
  }

  /// Prepend a QUIC varint length prefix to [data].
  static Uint8List encodeLengthPrefixed(Uint8List data) {
    final lengthBytes = VarInt.encode(data.length);
    final buffer = BytesBuilder();
    buffer.add(lengthBytes);
    buffer.add(data);
    return buffer.toBytes();
  }

  /// Read a varint length prefix and the following message from [data].
  ///
  /// Returns the decoded message and the total number of bytes consumed,
  /// or `null` if [data] is too short to contain a complete length-prefixed
  /// message.
  static (Uint8List message, int bytesConsumed)? parseLengthPrefixed(
    Uint8List data,
  ) {
    if (data.isEmpty) return null;
    final lengthFieldSize = VarInt.decodeLength(data[0]);
    if (data.length < lengthFieldSize) return null;

    final length = VarInt.decode(data.buffer, offset: data.offsetInBytes);
    final totalSize = lengthFieldSize + length;
    if (data.length < totalSize) return null;

    final message = data.sublist(lengthFieldSize, totalSize);
    return (message, totalSize);
  }
}

import 'dart:convert';
import 'dart:typed_data';

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

  /// Parse incoming multistream-select messages.
  static List<String> parseMessages(Uint8List bytes) {
    final text = utf8.decode(bytes);
    return text.split(newline).where((s) => s.isNotEmpty).toList();
  }
}

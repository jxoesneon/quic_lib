import 'dart:typed_data';

import 'qpack_encoder.dart';
import 'qpack_integer.dart';
import 'qpack_static_table.dart';
import 'qpack_string.dart';

/// An HTTP/3 response with status code, headers, and optional body.
class Http3Response {
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List? body;

  Http3Response({
    required this.statusCode,
    this.headers = const {},
    this.body,
  });

  /// Encode the response headers as a QPACK-encoded field section.
  ///
  /// The :status pseudo-header is encoded first, followed by regular headers.
  Uint8List encodeHeaders() {
    final lines = <({String name, String value})>[
      (name: ':status', value: statusCode.toString()),
    ];
    for (final entry in headers.entries) {
      lines.add((name: entry.key.toLowerCase(), value: entry.value));
    }
    return QpackEncoder.encodeFieldLines(lines);
  }

  /// Decode a QPACK-encoded field section into an [Http3Response].
  ///
  /// This is a simplified decoder that extracts the :status pseudo-header
  /// and treats the remainder as regular headers.
  static Http3Response decodeHeaders(Uint8List bytes) {
    final lines = _decodeFieldLines(bytes);

    int statusCode = 0;
    final headers = <String, String>{};

    for (final line in lines) {
      if (line.name == ':status') {
        statusCode = int.tryParse(line.value) ?? 0;
      } else {
        headers[line.name] = line.value;
      }
    }

    return Http3Response(statusCode: statusCode, headers: headers);
  }

  /// Simplified QPACK field-line decoder.
  ///
  /// Handles indexed and literal-with-name-reference encodings that use the
  /// static table, plus literal-without-name-reference.
  static List<({String name, String value})> _decodeFieldLines(
      Uint8List bytes) {
    final lines = <({String name, String value})>[];
    var offset = 0;

    while (offset < bytes.length) {
      final first = bytes[offset] & 0xFF;

      if ((first & 0x80) != 0) {
        // Indexed representation (1 prefix, 6-bit index)
        final (index, newOffset) = QpackInteger.decode(bytes, offset, 6);
        offset = newOffset;
        final entry = QpackStaticTable.get(index);
        if (entry != null) {
          lines.add(
            (
              name: entry.name,
              value: entry.value ?? '',
            ),
          );
        }
      } else if ((first & 0xE0) == 0x40) {
        // Literal with name reference (010 prefix, 5-bit name index)
        final (nameIndex, nameOffset) = QpackInteger.decode(bytes, offset, 5);
        offset = nameOffset;
        final entry = QpackStaticTable.get(nameIndex);
        final name = entry?.name ?? '';
        final (value, newOffset) = QpackString.decode(bytes, offset);
        offset = newOffset;
        lines.add((name: name, value: value));
      } else if ((first & 0xE0) == 0x20) {
        // Literal without name reference (001 prefix, then name, then value)
        offset++; // skip prefix byte
        final (name, nameOffset) = QpackString.decode(bytes, offset);
        offset = nameOffset;
        final (value, newOffset) = QpackString.decode(bytes, offset);
        offset = newOffset;
        lines.add((name: name, value: value));
      } else {
        // Unrecognized encoding; skip one byte to avoid infinite loop.
        offset++;
      }
    }

    return lines;
  }

  @override
  String toString() => 'Http3Response(status=$statusCode, headers=$headers)';
}

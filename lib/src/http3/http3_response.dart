import 'dart:typed_data';

import 'qpack_decoder.dart';
import 'qpack_encoder.dart';

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
  /// Extracts the :status pseudo-header and treats the remainder as regular headers.
  static Http3Response decodeHeaders(Uint8List bytes) {
    final lines = QpackDecoder.decodeFieldLines(bytes);

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

  @override
  String toString() => 'Http3Response(status=$statusCode, headers=$headers)';
}

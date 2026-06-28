import 'dart:typed_data';

import 'qpack_decoder.dart';
import 'qpack_encoder.dart';

/// An HTTP/3 request with pseudo-headers, regular headers, and optional body.
class Http3Request {
  final String method;
  final String path;
  final Map<String, String> headers;
  final Uint8List? body;

  Http3Request({
    required this.method,
    required this.path,
    this.headers = const {},
    this.body,
  });

  /// Encode the request headers as a QPACK-encoded field section.
  ///
  /// Pseudo-headers (:method, :path, :scheme, :authority) are encoded first,
  /// followed by regular headers.
  Uint8List encodeHeaders() {
    final lines = <({String name, String value})>[
      (name: ':method', value: method),
      (name: ':path', value: path),
      (name: ':scheme', value: 'https'),
      (name: ':authority', value: headers['host'] ?? ''),
    ];
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == 'host') continue;
      lines.add((name: entry.key.toLowerCase(), value: entry.value));
    }
    return QpackEncoder.encodeFieldLines(lines);
  }

  /// Decode a QPACK-encoded field section into an [Http3Request].
  ///
  /// Extracts pseudo-headers (:method, :path, :scheme, :authority) and
  /// treats the remainder as regular headers.
  static Http3Request decodeHeaders(Uint8List bytes) {
    final lines = QpackDecoder.decodeFieldLines(bytes);

    String method = '';
    String path = '';
    final headers = <String, String>{};

    for (final line in lines) {
      if (line.name == ':method') {
        method = line.value;
      } else if (line.name == ':path') {
        path = line.value;
      } else if (line.name == ':scheme') {
        // ignored for now
      } else if (line.name == ':authority') {
        headers['host'] = line.value;
      } else {
        headers[line.name] = line.value;
      }
    }

    return Http3Request(method: method, path: path, headers: headers);
  }

  @override
  String toString() => 'Http3Request($method $path, headers=$headers)';
}

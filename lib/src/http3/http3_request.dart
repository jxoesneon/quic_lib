import 'dart:typed_data';

import 'qpack_decoder.dart';
import 'qpack_encoder.dart';

/// An HTTP/3 request with pseudo-headers, regular headers, and optional body.
///
/// Represents a single HTTP/3 request message as defined in RFC 9114.
/// Pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) are
/// automatically generated during encoding; callers supply the HTTP method,
/// path, regular headers, and an optional binary body.
///
/// [Http3Request] objects are passed to [Http3Connection.sendRequest], which
/// QPACK-encodes the headers and stages the request on a new QUIC stream.
///
/// ## Example
/// ```dart
/// final request = Http3Request(
///   method: 'POST',
///   path: '/api/data',
///   headers: {
///     'host': 'example.com',
///     'content-type': 'application/json',
///   },
///   body: Uint8List.fromList(utf8.encode('{"key":"value"}')),
/// );
/// final encoded = request.encodeHeaders();
/// ```
///
/// See also:
/// - [Http3Connection.sendRequest] — sends this request over QUIC.
/// - [Http3Response] — the corresponding response type.
/// - RFC 9114 Section 4.1 — HTTP/3 Request Stream.
class Http3Request {
  /// The HTTP method (e.g. `'GET'`, `'POST'`, `'PUT'`).
  ///
  /// Encoded as the `:method` pseudo-header.
  final String method;

  /// The request target path (e.g. `'/index.html'`).
  ///
  /// Encoded as the `:path` pseudo-header.
  final String path;

  /// Regular HTTP headers (excluding pseudo-headers).
  ///
  /// The `host` header is mapped to the `:authority` pseudo-header during
  /// encoding. All other keys are lower-cased automatically.
  final Map<String, String> headers;

  /// The optional request body.
  ///
  /// When non-null and non-empty, [Http3Connection.sendRequest] writes the
  /// body as one or more HTTP/3 DATA frames.
  final Uint8List? body;

  /// Creates an HTTP/3 request.
  ///
  /// [method] and [path] are required. [headers] defaults to an empty map and
  /// [body] defaults to null.
  Http3Request({
    required this.method,
    required this.path,
    this.headers = const {},
    this.body,
  });

  /// Encode the request headers as a QPACK-encoded field section.
  ///
  /// Pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) are encoded
  /// first, followed by regular headers. The `host` header is promoted to
  /// `:authority`; all other header names are lower-cased.
  ///
  /// The returned bytes are suitable for an HTTP/3 HEADERS frame payload.
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
  /// Extracts pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) and
  /// treats the remainder as regular headers. `:authority` is stored under
  /// the `host` key. The `:scheme` pseudo-header is currently ignored.
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

import 'dart:typed_data';

import 'qpack_decoder.dart';
import 'qpack_encoder.dart';

/// An HTTP/3 response with status code, headers, and optional body.
///
/// Represents a single HTTP/3 response message as defined in RFC 9114.
/// The `:status` pseudo-header is extracted during decoding and exposed as
/// the integer [statusCode]. Regular headers are stored in [headers] with
/// lower-cased keys. An optional binary [body] may be attached for responses
/// that carry payload.
///
/// [Http3Response] objects are typically obtained via
/// [Http3Connection.getResponse] after the peer has sent HEADERS and DATA
/// frames on a request stream.
///
/// ## Example
/// ```dart
/// final response = Http3Response(
///   statusCode: 200,
///   headers: {
///     'content-type': 'text/html',
///     'cache-control': 'no-cache',
///   },
///   body: Uint8List.fromList(utf8.encode('<h1>Hello</h1>')),
/// );
/// final encoded = response.encodeHeaders();
/// ```
///
/// See also:
/// - [Http3Connection.getResponse] — retrieves a response for a given stream.
/// - [Http3Request] — the corresponding request type.
/// - RFC 9114 Section 4.1 — HTTP/3 Response Stream.
class Http3Response {
  /// The HTTP status code (e.g. `200`, `404`, `500`).
  ///
  /// Encoded as the `:status` pseudo-header.
  final int statusCode;

  /// Regular HTTP response headers.
  ///
  /// Header names are lower-cased during encoding and decoding.
  final Map<String, String> headers;

  /// The optional response body.
  ///
  /// This field holds the raw payload bytes. In [Http3Connection] the body
  /// is typically delivered via DATA frames and reassembled with `getBody`.
  final Uint8List? body;

  /// Creates an HTTP/3 response.
  ///
  /// [statusCode] is required. [headers] defaults to an empty map and
  /// [body] defaults to null.
  Http3Response({
    required this.statusCode,
    this.headers = const {},
    this.body,
  });

  /// Encode the response headers as a QPACK-encoded field section.
  ///
  /// The `:status` pseudo-header is encoded first, followed by regular
  /// headers with lower-cased names. The returned bytes are suitable for
  /// an HTTP/3 HEADERS frame payload.
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
  /// Extracts the `:status` pseudo-header and treats the remainder as regular
  /// headers. If `:status` cannot be parsed as an integer, it defaults to `0`.
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

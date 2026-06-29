import 'dart:typed_data';

import 'qpack_decoder.dart';
import 'qpack_encoder.dart';

/// An Extended CONNECT request (RFC 9220) used to bootstrap protocols such as
/// WebTransport or WebSockets over HTTP/3.
///
/// In addition to the standard HTTP/3 pseudo-headers (`:method`, `:scheme`,
/// `:authority`, `:path`), this request carries a `:protocol` pseudo-header
/// that identifies the desired application protocol (e.g. `"webtransport"` or
/// `"websocket"`).
///
/// The `:method` is always `"CONNECT"`.
class ExtendedConnectRequest {
  /// The `:protocol` pseudo-header (e.g. `"webtransport"`, `"websocket"`).
  final String protocol;

  /// The `:scheme` pseudo-header (defaults to `"https"`).
  final String scheme;

  /// The `:authority` pseudo-header.
  final String authority;

  /// The `:path` pseudo-header.
  ///
  /// Per RFC 9114 Erratum 7702, paths starting with `"//"` are valid
  /// and MUST NOT be rejected.
  final String path;

  /// Regular HTTP headers (excluding pseudo-headers).
  final Map<String, String> headers;

  /// Optional request body.
  final Uint8List? body;

  ExtendedConnectRequest({
    required this.protocol,
    this.scheme = 'https',
    required this.authority,
    required this.path,
    this.headers = const {},
    this.body,
  });

  /// Encode the request headers as a QPACK-encoded field section.
  ///
  /// [encoder] may be used to emit dynamic table insertions on the QPACK
  /// encoder stream. When omitted, only the static table is used.
  Uint8List encodeHeaders({QpackEncoder? encoder}) {
    final lines = <({String name, String value})>[
      (name: ':method', value: 'CONNECT'),
      (name: ':scheme', value: scheme),
      (name: ':authority', value: authority),
      (name: ':path', value: path),
      (name: ':protocol', value: protocol),
    ];
    for (final entry in headers.entries) {
      lines.add((name: entry.key.toLowerCase(), value: entry.value));
    }
    if (encoder != null) {
      return encoder.encodeLines(lines);
    }
    return QpackEncoder.encodeFieldLines(lines);
  }

  /// Decode a QPACK-encoded field section into an [ExtendedConnectRequest].
  static ExtendedConnectRequest decodeHeaders(Uint8List bytes) {
    final lines = QpackDecoder.decodeFieldLines(bytes);

    String protocol = '';
    String scheme = '';
    String authority = '';
    String path = '';
    final headers = <String, String>{};

    for (final line in lines) {
      switch (line.name) {
        case ':protocol':
          protocol = line.value;
        case ':scheme':
          scheme = line.value;
        case ':authority':
          authority = line.value;
        case ':path':
          path = line.value;
        case ':method':
          // ignored, always CONNECT
          break;
        default:
          headers[line.name] = line.value;
      }
    }

    return ExtendedConnectRequest(
      protocol: protocol,
      scheme: scheme,
      authority: authority,
      path: path,
      headers: headers,
    );
  }

  @override
  String toString() =>
      'ExtendedConnectRequest(:protocol=$protocol $path, headers=$headers)';
}

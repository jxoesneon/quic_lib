/// HTTP/3 stream types per RFC 9114 Section 4.1.
enum Http3StreamType {
  /// QUIC stream carrying HTTP/3 control frames.
  control,

  /// Server push stream (server-initiated unidirectional).
  push,

  /// Client-initiated bidirectional stream carrying a single request/response.
  request,

  /// Reserved stream type for future use.
  reserved,
}

/// Unidirectional stream type identifiers per RFC 9114 Section 6.2.
///
/// Each unidirectional stream begins with a single varint-encoded stream type.
enum StreamType {
  /// Control stream (RFC 9114 Section 6.2.1).
  control(0x00),

  /// Push stream (RFC 9114 Section 6.2.2).
  push(0x01),

  /// QPACK encoder stream (RFC 9204 Section 4.2).
  qpackEncoder(0x02),

  /// QPACK decoder stream (RFC 9204 Section 4.2).
  qpackDecoder(0x03);

  final int value;
  const StreamType(this.value);

  /// Looks up a stream type by its wire value.
  static StreamType? fromValue(int value) {
    for (final type in values) {
      if (type.value == value) return type;
    }
    return null;
  }
}

/// Handles classification of an HTTP/3 stream based on its QUIC stream ID.
///
/// Per RFC 9114 §4.1:
/// - Control stream: stream ID 0x00 for client, 0x01 for server
/// - Push stream: server-initiated unidirectional (type bits = 0x03)
/// - Request stream: client-initiated bidirectional (type bits = 0x00)
class Http3StreamHandler {
  final int streamId;
  final bool isServer;

  Http3StreamHandler(this.streamId, {this.isServer = false});

  /// Determine the HTTP/3 stream type from the QUIC stream ID.
  ///
  /// [isServer] indicates whether this endpoint is acting as the server.
  static Http3StreamType typeFromStreamId(int streamId, bool isServer) {
    // Control stream: 0x00 for client, 0x01 for server
    if (!isServer && streamId == 0x00) {
      return Http3StreamType.control;
    }
    if (isServer && streamId == 0x01) {
      return Http3StreamType.control;
    }

    // Push stream: server-initiated unidirectional (type bits = 0x03)
    if ((streamId & 0x03) == 0x03) {
      return Http3StreamType.push;
    }

    // Request stream: client-initiated bidirectional (type bits = 0x00)
    if ((streamId & 0x03) == 0x00) {
      return Http3StreamType.request;
    }

    return Http3StreamType.reserved;
  }

  /// Is this a control stream?
  bool get isControlStream =>
      typeFromStreamId(streamId, isServer) == Http3StreamType.control;

  /// Is this a request stream?
  bool get isRequestStream =>
      typeFromStreamId(streamId, isServer) == Http3StreamType.request;

  /// Is this a push stream?
  bool get isPushStream =>
      typeFromStreamId(streamId, isServer) == Http3StreamType.push;
}

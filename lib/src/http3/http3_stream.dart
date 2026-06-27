/// HTTP/3 stream types per RFC 9114 Section 4.1.
enum Http3StreamType {
  control,
  push,
  request,
  reserved,
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

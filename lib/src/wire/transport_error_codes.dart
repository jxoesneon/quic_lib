/// QUIC transport error codes per RFC 9000 Section 20.1.
///
/// These codes are used in CONNECTION_CLOSE frames to signal why
/// a connection was terminated. Application error codes (0x4000-0xffff)
/// are application-defined and not enumerated here.
enum QuicTransportErrorCode {
  /// No error (0x00). Used when closing a connection without an error.
  noError(0x00),

  /// Internal error (0x01). The endpoint encountered an internal error.
  internalError(0x01),

  /// Connection refused (0x02). The server refused the connection.
  connectionRefused(0x02),

  /// Flow control error (0x03). The endpoint received too much data.
  flowControlError(0x03),

  /// Stream limit error (0x04). The peer opened too many streams.
  streamLimitError(0x04),

  /// Stream state error (0x05). The peer violated stream state machine.
  streamStateError(0x05),

  /// Final size error (0x06). The peer changed the final size of a stream.
  finalSizeError(0x06),

  /// Frame encoding error (0x07). The peer sent a malformed frame.
  frameEncodingError(0x07),

  /// Transport parameter error (0x08). The peer sent invalid transport params.
  transportParameterError(0x08),

  /// Connection ID limit error (0x09). The peer sent too many connection IDs.
  connectionIdLimitError(0x09),

  /// Protocol violation (0x0a). The peer violated a MUST in the RFC.
  protocolViolation(0x0a),

  /// Invalid token (0x0b). The server received an invalid token.
  invalidToken(0x0b),

  /// Application error (0x0c). Generic application close code.
  applicationError(0x0c),

  /// Crypto buffer exceeded (0x0d). CRYPTO data exceeded buffer limit.
  cryptoBufferExceeded(0x0d),

  /// Key update error (0x0e). The peer performed an invalid key update.
  keyUpdateError(0x0e),

  /// AEAD limit reached (0x0f). Packet protection integrity limit reached.
  aeadLimitReached(0x0f),

  /// No viable path (0x10). No network path available to the peer.
  noViablePath(0x10);

  final int value;
  const QuicTransportErrorCode(this.value);

  /// Look up a known transport error code by value.
  static QuicTransportErrorCode? fromValue(int value) {
    for (final code in values) {
      if (code.value == value) return code;
    }
    return null;
  }
}

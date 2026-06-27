/// WebTransport stream type discriminator.
///
/// WebTransport runs over HTTP/3, which in turn uses QUIC streams.
/// Stream IDs are 62-bit unsigned integers encoded as QUIC varints.
/// The two least-significant bits encode the stream type:
///   Bit 0: 0 = client-initiated, 1 = server-initiated
///   Bit 1: 0 = bidirectional,     1 = unidirectional
///
/// See RFC 9000 Section 2.1 and the WebTransport over HTTP/3 specification.
enum WebTransportStreamType {
  bidirectional,
  unidirectional,
}

/// Discriminator and encoder/decoder for WebTransport stream IDs.
class WebTransportStreamId {
  /// Two-bit type constant for a client-initiated bidirectional stream.
  static const int typeClientBidi = 0x00;

  /// Two-bit type constant for a server-initiated bidirectional stream.
  static const int typeServerBidi = 0x01;

  /// Two-bit type constant for a client-initiated unidirectional stream.
  static const int typeClientUni = 0x02;

  /// Two-bit type constant for a server-initiated unidirectional stream.
  static const int typeServerUni = 0x03;

  WebTransportStreamId._();

  /// Returns the directionality of the given [streamId].
  static WebTransportStreamType getType(int streamId) {
    return (_typeBits(streamId) & 0x02) == 0
        ? WebTransportStreamType.bidirectional
        : WebTransportStreamType.unidirectional;
  }

  /// Returns `true` if [streamId] was opened by the client.
  static bool isClientInitiated(int streamId) {
    return (_typeBits(streamId) & 0x01) == 0;
  }

  /// Returns `true` if [streamId] was opened by the server.
  static bool isServerInitiated(int streamId) {
    return (_typeBits(streamId) & 0x01) != 0;
  }

  /// Encodes a [type] constant and [sequence] number into a stream ID.
  ///
  /// [type] must be one of the `type*` constants (0..3).
  /// [sequence] is the zero-based sequence number within that type.
  static int encode({required int type, required int sequence}) {
    return type + (4 * sequence);
  }

  /// Extracts the sequence number from [streamId].
  static int sequence(int streamId) {
    return streamId >> 2;
  }

  static int _typeBits(int streamId) {
    return streamId & 0x03;
  }
}

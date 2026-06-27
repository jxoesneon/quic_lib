/// QUIC Stream ID encoding and allocation.
///
/// Based on RFC 9000 Section 2.1:
///   stream_id = (type_bits) + 4 * sequence_number
/// where the two least-significant bits encode stream type:
///   0b00 = client-initiated bidirectional
///   0b01 = server-initiated bidirectional
///   0b10 = client-initiated unidirectional
///   0b11 = server-initiated unidirectional
class StreamId {
  static const int typeClientBidi = 0x00;
  static const int typeServerBidi = 0x01;
  static const int typeClientUni = 0x02;
  static const int typeServerUni = 0x03;

  /// Encode stream type and sequence into a stream ID.
  ///
  /// [type] must be one of the `type*` constants (0..3).
  /// [sequence] is the stream sequence number (0, 1, 2, …).
  static int encode({required int type, required int sequence}) {
    return type + (4 * sequence);
  }

  /// Decode a stream ID into its type and sequence number.
  static ({int type, int sequence}) decode(int streamId) {
    final type = typeBits(streamId);
    final sequence = streamId >> 2; // equivalent to (streamId - type) ~/ 4
    return (type: type, sequence: sequence);
  }

  /// Returns `true` if [streamId] is client-initiated.
  ///
  /// Client-initiated types have bit 0 cleared (0bx0).
  static bool isClientInitiated(int streamId) {
    return (typeBits(streamId) & 0x01) == 0;
  }

  /// Returns `true` if [streamId] is server-initiated.
  ///
  /// Server-initiated types have bit 0 set (0bx1).
  static bool isServerInitiated(int streamId) {
    return (typeBits(streamId) & 0x01) != 0;
  }

  /// Returns `true` if [streamId] is bidirectional.
  ///
  /// Bidirectional types have bit 1 cleared (0b0x).
  static bool isBidirectional(int streamId) {
    return (typeBits(streamId) & 0x02) == 0;
  }

  /// Returns `true` if [streamId] is unidirectional.
  ///
  /// Unidirectional types have bit 1 set (0b1x).
  static bool isUnidirectional(int streamId) {
    return (typeBits(streamId) & 0x02) != 0;
  }

  /// Extract the type bits (bottom 2 bits) from a stream ID.
  static int typeBits(int streamId) {
    return streamId & 0x03;
  }

  /// Extract the sequence number from a stream ID.
  static int sequence(int streamId) {
    return streamId >> 2;
  }
}

/// Allocates stream IDs for each of the four QUIC stream categories.
class StreamIdAllocator {
  int _clientBidiNext = 0;
  int _serverBidiNext = 0;
  int _clientUniNext = 0;
  int _serverUniNext = 0;

  /// Maximum stream ID allowed (2^62 - 1).
  static const int maxStreamId = 4611686018427387903;

  /// Allocate the next client-initiated bidirectional stream ID.
  int allocateClientBidi() {
    final seq = _clientBidiNext;
    final id = StreamId.encode(type: StreamId.typeClientBidi, sequence: seq);
    if (id > maxStreamId) {
      throw StateError('Client bidi stream ID limit exceeded');
    }
    _clientBidiNext++;
    return id;
  }

  /// Allocate the next server-initiated bidirectional stream ID.
  int allocateServerBidi() {
    final seq = _serverBidiNext;
    final id = StreamId.encode(type: StreamId.typeServerBidi, sequence: seq);
    if (id > maxStreamId) {
      throw StateError('Server bidi stream ID limit exceeded');
    }
    _serverBidiNext++;
    return id;
  }

  /// Allocate the next client-initiated unidirectional stream ID.
  int allocateClientUni() {
    final seq = _clientUniNext;
    final id = StreamId.encode(type: StreamId.typeClientUni, sequence: seq);
    if (id > maxStreamId) {
      throw StateError('Client uni stream ID limit exceeded');
    }
    _clientUniNext++;
    return id;
  }

  /// Allocate the next server-initiated unidirectional stream ID.
  int allocateServerUni() {
    final seq = _serverUniNext;
    final id = StreamId.encode(type: StreamId.typeServerUni, sequence: seq);
    if (id > maxStreamId) {
      throw StateError('Server uni stream ID limit exceeded');
    }
    _serverUniNext++;
    return id;
  }
}

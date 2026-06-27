import 'dart:typed_data';

import '../wire/frame.dart';
import 'quic_stream.dart';
import 'receive_state_machine.dart';

/// Routes incoming STREAM frames to the correct [QuicStream] instance.
///
/// Per RFC 9000, stream IDs are structured:
/// - Client bidirectional: 0, 4, 8, ...
/// - Server bidirectional: 1, 5, 9, ...
/// - Client unidirectional: 2, 6, 10, ...
/// - Server unidirectional: 3, 7, 11, ...
///
/// **Status:** Scaffold — stores and routes frames but full stream lifecycle
/// (flow control, state machine integration) is not yet wired.
class StreamManager {
  final Map<int, QuicStream> _streams = {};

  /// Deliver a STREAM frame to the appropriate stream.
  /// Creates the stream if it does not exist.
  void onStreamFrame(StreamFrame frame) {
    final stream = _streams.putIfAbsent(
      frame.streamId,
      () => QuicReceiveStream(
        frame.streamId,
        stateMachine: ReceiveStateMachine(),
      ),
    ) as QuicReceiveStream;
    final int offset = frame.offset ?? 0;
    final Uint8List data = frame.data is Uint8List
        ? frame.data as Uint8List
        : Uint8List.fromList(frame.data);
    final int bytesReceived = offset + data.length;
    stream.deliver(
      data,
      fin: frame.fin,
      finalSize: frame.fin ? bytesReceived : null,
      bytesReceived: bytesReceived,
    );
  }

  /// Get an existing stream by ID.
  QuicStream? getStream(int streamId) => _streams[streamId];

  /// All active streams.
  Iterable<QuicStream> get streams => _streams.values;

  /// Remove a closed stream.
  void removeStream(int streamId) {
    _streams.remove(streamId);
  }

  /// Reset all state.
  void reset() {
    _streams.clear();
  }
}

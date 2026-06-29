import 'dart:typed_data';

import '../wire/frame.dart';
import 'flow_controller.dart';
import 'quic_stream.dart';
import 'receive_state_machine.dart';
import 'send_state_machine.dart';
import 'stream_scheduler.dart';

/// Routes incoming STREAM frames to the correct [QuicStream] instance.
///
/// Per RFC 9000, stream IDs are structured:
/// - Client bidirectional: 0, 4, 8, ...
/// - Server bidirectional: 1, 5, 9, ...
/// - Client unidirectional: 2, 6, 10, ...
/// - Server unidirectional: 3, 7, 11, ...
class StreamManager {
  final Map<int, QuicStream> _streams = {};
  final Map<int, FlowController> _sendFlowControllers = {};
  final Map<int, FlowController> _receiveFlowControllers = {};

  /// Deliver a STREAM frame to the appropriate stream.
  /// Creates the stream if it does not exist.
  ///
  /// [isEarlyData] is true when the frame was received in a 0-RTT packet.
  void onStreamFrame(StreamFrame frame, {bool isEarlyData = false}) {
    final bool isNew = !_streams.containsKey(frame.streamId);
    final stream = _streams.putIfAbsent(
      frame.streamId,
      () => QuicReceiveStream(
        frame.streamId,
        stateMachine: ReceiveStateMachine(),
        isEarlyData: isEarlyData,
      ),
    ) as QuicReceiveStream;

    if (isNew) {
      _sendFlowControllers[frame.streamId] =
          FlowController(initialLimit: 65536);
      _receiveFlowControllers[frame.streamId] =
          FlowController(initialLimit: 65536);
    }

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

    final receiveFlowController = _receiveFlowControllers[frame.streamId];
    receiveFlowController?.consume(frame.data.length);
  }

  /// Create a send-side stream for [streamId].
  ///
  /// Set [isEarlyData] to true when the stream is opened in a 0-RTT flight.
  QuicSendStream createSendStream(int streamId, {bool isEarlyData = false}) {
    final stream = QuicSendStream(
      streamId,
      stateMachine: SendStateMachine(),
      isEarlyData: isEarlyData,
    );
    _streams[streamId] = stream;
    _sendFlowControllers[streamId] = FlowController(initialLimit: 65536);
    _receiveFlowControllers[streamId] = FlowController(initialLimit: 65536);
    return stream;
  }

  /// Get an existing stream by ID.
  QuicStream? getStream(int streamId) => _streams[streamId];

  /// Get the send flow controller for a stream.
  FlowController? getSendFlowController(int streamId) =>
      _sendFlowControllers[streamId];

  /// Get the receive flow controller for a stream.
  FlowController? getReceiveFlowController(int streamId) =>
      _receiveFlowControllers[streamId];

  /// All active streams.
  Iterable<QuicStream> get streams => _streams.values;

  /// All active stream IDs.
  Iterable<int> get streamIds => _streams.keys;

  /// The current stream scheduler, or null if none is set.
  StreamScheduler? scheduler;

  /// Select the next stream for processing using the configured scheduler.
  ///
  /// Returns the first active stream if no scheduler is set. Returns `null`
  /// when no streams are active.
  QuicStream? selectNextStream() {
    final ids = _streams.keys.toList();
    if (ids.isEmpty) return null;
    if (scheduler != null) {
      final nextId = scheduler!.selectNextStream(ids);
      return _streams[nextId];
    }
    return _streams.values.first;
  }

  /// Remove a closed stream.
  void removeStream(int streamId) {
    _streams.remove(streamId);
  }

  /// Reset all state.
  void reset() {
    _streams.clear();
  }

  /// Check if there is enough send window to send [bytes] on [streamId].
  bool canSendOnStream(int streamId, int bytes) {
    final controller = _sendFlowControllers[streamId];
    if (controller == null) return false;
    return controller.availableWindow >= bytes;
  }

  /// Update the send flow controller limit for [streamId].
  void updateSendWindow(int streamId, int newLimit) {
    _sendFlowControllers[streamId]?.updateLimit(newLimit);
  }

  /// Clear all flow controllers.
  void resetFlowControl() {
    _sendFlowControllers.clear();
    _receiveFlowControllers.clear();
  }
}

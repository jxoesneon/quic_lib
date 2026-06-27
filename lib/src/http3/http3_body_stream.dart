import 'dart:async';
import 'dart:typed_data';

import 'data_frame.dart';

/// Wraps a stream of HTTP/3 DATA frames for a single QUIC stream.
///
/// As DATA frames arrive they are exposed as individual chunks. An empty
/// DATA frame payload is treated as an EOF marker (per HTTP/3 streaming
/// conventions).
class Http3BodyStream {
  final StreamController<Uint8List> _chunkController;
  final List<Uint8List> _bufferedChunks = [];
  bool _isComplete = false;

  Http3BodyStream() : _chunkController = StreamController<Uint8List>.broadcast();

  /// Yield each DATA frame's payload as it arrives.
  Stream<Uint8List> get chunks => _chunkController.stream;

  /// True when an EOF-marker (empty DATA frame) has been received.
  bool get isComplete => _isComplete;

  /// Concatenate all received chunks into a single buffer.
  ///
  /// Completes once [isComplete] becomes true. If the stream is already
  /// complete, returns the buffered body immediately.
  Future<Uint8List> get fullBody async {
    if (_isComplete) {
      return _concatenate();
    }
    await _chunkController.done;
    return _concatenate();
  }

  /// Deliver a new DATA frame into this body stream.
  void addFrame(Http3DataFrame frame) {
    if (_isComplete) return;
    if (frame.data.isEmpty) {
      _isComplete = true;
      _chunkController.close();
      return;
    }
    final bytes = Uint8List.fromList(frame.data);
    _bufferedChunks.add(bytes);
    _chunkController.add(bytes);
  }

  Uint8List _concatenate() {
    if (_bufferedChunks.isEmpty) return Uint8List(0);
    final totalLength = _bufferedChunks.fold<int>(0, (sum, c) => sum + c.length);
    final result = Uint8List(totalLength);
    var offset = 0;
    for (final chunk in _bufferedChunks) {
      result.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    return result;
  }
}

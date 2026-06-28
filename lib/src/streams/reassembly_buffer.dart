import 'dart:typed_data';

/// Reassembles out-of-order STREAM frame data into contiguous byte sequences.
class ReassemblyBuffer {
  // SECURITY: Limits to prevent memory exhaustion DoS.
  static const int maxBufferSize = 16 * 1024 * 1024; // 16 MB
  static const int maxOffsetGap = 16 * 1024 * 1024; // 16 MB
  static const int maxFragmentCount = 1024;

  final Map<int, List<int>> _buffer = {};
  int _readOffset = 0;
  int? _finalSize;
  int _bufferedBytes = 0;

  /// Insert data at a given offset.
  ///
  /// Throws [StateError] if limits would be exceeded.
  void insert(int offset, List<int> data) {
    if (data.isEmpty) return;

    // SECURITY: Reject data past max offset gap to prevent sparse-buffer DoS.
    if (offset - _readOffset > maxOffsetGap) {
      throw StateError(
          'ReassemblyBuffer: offset gap exceeds max ($maxOffsetGap)');
    }

    // SECURITY: Reject if total buffered bytes would exceed max.
    if (_bufferedBytes + data.length > maxBufferSize) {
      throw StateError(
          'ReassemblyBuffer: size limit ($maxBufferSize) exceeded');
    }

    // SECURITY: Reject if fragment count would exceed max.
    final newFragment = !_buffer.containsKey(offset);
    if (newFragment && _buffer.length >= maxFragmentCount) {
      throw StateError(
          'ReassemblyBuffer: fragment limit ($maxFragmentCount) exceeded');
    }

    _buffer[offset] = data;
    _bufferedBytes += data.length;
  }

  /// Read contiguous data starting from the current read offset.
  /// Returns null if no contiguous data is available.
  Uint8List? read() {
    final builder = BytesBuilder();
    while (_buffer.containsKey(_readOffset)) {
      final data = _buffer.remove(_readOffset)!;
      builder.add(data);
      _readOffset += data.length;
      _bufferedBytes -= data.length;
    }
    final result = builder.toBytes();
    return result.isEmpty ? null : Uint8List.fromList(result);
  }

  /// True if all data up to finalSize has been read.
  bool get isComplete {
    if (_finalSize == null) return false;
    return _readOffset >= _finalSize!;
  }

  /// Current read offset.
  int get readOffset => _readOffset;

  /// Set the final size when FIN is received.
  set finalSize(int? size) {
    _finalSize = size;
  }

  /// Reset the buffer.
  void reset() {
    _buffer.clear();
    _readOffset = 0;
    _finalSize = null;
    _bufferedBytes = 0;
  }

  /// True if there are buffered bytes at offsets beyond the read offset.
  bool get hasGaps {
    if (_buffer.isEmpty) return false;
    return _buffer.keys.any((offset) => offset > _readOffset);
  }
}

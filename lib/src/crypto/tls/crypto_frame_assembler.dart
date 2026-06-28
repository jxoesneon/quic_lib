import 'dart:typed_data';

import 'package:quic_lib/src/wire/frame.dart';

/// Assembles out-of-order CRYPTO frames into contiguous TLS message bytes.
class CryptoFrameAssembler {
  // SECURITY: Limits to prevent memory exhaustion DoS via pathological CRYPTO frames.
  static const int maxBufferSize =
      4 * 1024 * 1024; // 4 MB for TLS handshake data
  static const int maxOffsetGap = 4 * 1024 * 1024; // 4 MB
  static const int maxFragmentCount = 256;

  /// Buffer of received CRYPTO data, keyed by offset.
  final Map<int, List<int>> _buffer = {};
  int _readOffset = 0;
  int _bufferedBytes = 0;

  /// Get the next expected offset.
  int get nextOffset => _readOffset;

  /// Check if there are gaps in the buffer.
  bool get hasGaps => _buffer.keys.any((off) => off > _readOffset);

  /// Deliver a CRYPTO frame. Returns contiguous completed messages if any.
  ///
  /// Throws [StateError] if limits would be exceeded.
  List<Uint8List> deliver(CryptoFrame frame) {
    // Discard any buffered data that is entirely behind the current read offset.
    _buffer.removeWhere((off, data) => off + data.length <= _readOffset);

    final frameEnd = frame.offset + frame.data.length;
    if (frameEnd <= _readOffset) {
      // Entire frame is behind us; ignore.
      return [];
    }

    int storeOffset = frame.offset;
    List<int> storeData = List<int>.from(frame.data);

    // If the frame overlaps already-consumed bytes, trim the leading bytes.
    if (storeOffset < _readOffset) {
      final trim = _readOffset - storeOffset;
      storeData = storeData.sublist(trim);
      storeOffset = _readOffset;
    }

    // SECURITY: Validate against limits before storing.
    if (storeOffset - _readOffset > maxOffsetGap) {
      throw StateError(
          'CryptoFrameAssembler: offset gap exceeds max ($maxOffsetGap)');
    }
    if (_bufferedBytes + storeData.length > maxBufferSize) {
      throw StateError(
          'CryptoFrameAssembler: size limit ($maxBufferSize) exceeded');
    }
    final newFragment = !_buffer.containsKey(storeOffset);
    if (newFragment && _buffer.length >= maxFragmentCount) {
      throw StateError(
          'CryptoFrameAssembler: fragment limit ($maxFragmentCount) exceeded');
    }

    _buffer[storeOffset] = storeData;
    _bufferedBytes += storeData.length;

    final result = <Uint8List>[];

    // While we have data starting exactly at the read offset, consume the
    // longest contiguous run and yield it as a completed message.
    while (_buffer.containsKey(_readOffset)) {
      final chunk = <int>[];
      var currentOffset = _readOffset;

      while (_buffer.containsKey(currentOffset)) {
        final data = _buffer.remove(currentOffset)!;
        chunk.addAll(data);
        _bufferedBytes -= data.length;
        currentOffset += data.length;
      }

      result.add(Uint8List.fromList(chunk));
      _readOffset = currentOffset;
    }

    return result;
  }

  /// Reset the assembler (e.g., on connection close).
  void reset() {
    _buffer.clear();
    _readOffset = 0;
    _bufferedBytes = 0;
  }
}

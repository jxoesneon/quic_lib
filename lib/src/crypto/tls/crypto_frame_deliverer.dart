import 'dart:typed_data';

import 'package:quic_lib/src/wire/frame.dart';

/// Chunks a large TLS message into CRYPTO frames respecting a max frame size.
class CryptoFrameDeliverer {
  /// Current write offset in the CRYPTO stream.
  int _writeOffset = 0;

  /// Current write offset.
  int get writeOffset => _writeOffset;

  /// Chunk a large TLS message into CRYPTO frames respecting max frame size.
  /// [maxFrameSize] defaults to 1200 bytes.
  List<CryptoFrame> chunk(Uint8List message, {int maxFrameSize = 1200}) {
    // SECURITY: Reject invalid maxFrameSize values.
    if (maxFrameSize <= 0) {
      throw ArgumentError('maxFrameSize must be positive, got $maxFrameSize');
    }
    final frames = <CryptoFrame>[];
    var messageOffset = 0;

    while (messageOffset < message.length) {
      final end = messageOffset + maxFrameSize > message.length
          ? message.length
          : messageOffset + maxFrameSize;
      final chunk = message.sublist(messageOffset, end);
      frames.add(CryptoFrame(offset: _writeOffset, data: chunk));
      _writeOffset += chunk.length;
      messageOffset += chunk.length;
    }

    return frames;
  }

  /// Reset deliverer state.
  void reset() {
    _writeOffset = 0;
  }
}

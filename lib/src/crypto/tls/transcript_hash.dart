import 'dart:typed_data';

import 'package:dart_quic/src/crypto/crypto_backend.dart';

/// Maintains a running TLS 1.3 transcript hash.
///
/// In real TLS 1.3, the transcript hash is computed as
/// Hash(message1 || message2 || ...).
/// This scaffold maintains a byte buffer and hashes it on each addition.
class TranscriptHash {
  final CryptoBackend _backend;
  final BytesBuilder _buffer;
  List<int> _currentHash;

  /// Creates a new [TranscriptHash] using the given [backend] for SHA-256.
  TranscriptHash(CryptoBackend backend)
      : _backend = backend,
        _buffer = BytesBuilder(),
        _currentHash = <int>[];

  /// Appends [message] to the internal buffer and recomputes the running
  /// SHA-256 hash over the entire buffer.
  Future<void> addMessage(List<int> message) async {
    _buffer.add(message);
    _currentHash = await _backend.sha256(_buffer.toBytes());
  }

  /// Returns the current hash value (the hash of all messages added so far).
  List<int> get currentHash => _currentHash;

  /// Clears the buffer and the current hash.
  void reset() {
    _buffer.clear();
    _currentHash = <int>[];
  }
}

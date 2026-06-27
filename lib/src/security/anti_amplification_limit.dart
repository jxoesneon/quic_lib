/// Anti-amplification limit tracker per RFC 9000 Section 8.
///
/// Before address validation, an endpoint MUST NOT send more than
/// 3 times the number of bytes it has received from the peer.
class AntiAmplificationLimit {
  /// Bytes received from the peer.
  int _bytesReceived = 0;

  /// Bytes sent to the peer.
  int _bytesSent = 0;

  /// Amplification factor (default 3 per RFC 9000 §8).
  static const int amplificationFactor = 3;

  /// Address has been validated (e.g., via RETRY or ADDRESS_VALIDATION frame).
  bool _addressValidated = false;

  /// Record received bytes.
  void onBytesReceived(int bytes) {
    if (bytes < 0) {
      throw ArgumentError('bytes must be non-negative, got $bytes');
    }
    if (bytes > 0) {
      _bytesReceived += bytes;
    }
  }

  /// Record sent bytes.
  void onBytesSent(int bytes) {
    if (bytes < 0) {
      throw ArgumentError('bytes must be non-negative, got $bytes');
    }
    if (bytes > 0) {
      _bytesSent += bytes;
    }
  }

  /// Mark peer address as validated.
  void validateAddress() {
    _addressValidated = true;
  }

  /// Can we send [bytes] without exceeding the amplification limit?
  bool canSend(int bytes) {
    if (_addressValidated) return true;
    if (bytes <= 0) return true;
    return sendBudget >= bytes;
  }

  /// Current send budget.
  int get sendBudget {
    if (_addressValidated) {
      // Represent "infinity" as Dart's maximum integer value.
      return 0x7FFFFFFFFFFFFFFF;
    }
    final budget = (_bytesReceived * amplificationFactor) - _bytesSent;
    return budget < 0 ? 0 : budget;
  }

  /// Reset all tracked state.
  void reset() {
    _bytesReceived = 0;
    _bytesSent = 0;
    _addressValidated = false;
  }
}

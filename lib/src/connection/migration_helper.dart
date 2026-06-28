import 'dart:math';

import 'package:quic_lib/src/wire/frame.dart';

/// Helper for QUIC connection path validation via PATH_CHALLENGE / PATH_RESPONSE.
///
/// RFC 9000 Section 8.2: A path is considered validated when a PATH_RESPONSE
/// frame is received that echoes the data sent in a PATH_CHALLENGE frame.
class MigrationHelper {
  // SECURITY: Limits to prevent memory exhaustion DoS.
  static const int maxPendingChallenges = 8;
  static const int maxValidatedPaths = 16;

  /// Active path challenges: challenge_data → sent_time_us.
  final Map<List<int>, int> _pendingChallenges = {};

  /// Validated paths: hex-encoded challenge_data stored after response.
  final Set<String> _validatedPaths = {};

  /// Default path validation timeout in microseconds.
  static const int defaultTimeoutUs = 5000;

  /// Generate a new PATH_CHALLENGE frame.
  ///
  /// Creates 8 bytes of cryptographically secure random data, records the
  /// send time, and returns a [PathChallengeFrame].
  PathChallengeFrame generateChallenge({int? currentTimeUs}) {
    // SECURITY: Evict oldest if at capacity.
    if (_pendingChallenges.length >= maxPendingChallenges) {
      _evictOldestChallenge();
    }
    final random = Random.secure();
    final data = List<int>.generate(8, (_) => random.nextInt(256));
    _pendingChallenges[data] = currentTimeUs ?? _nowUs();
    return PathChallengeFrame(data: data);
  }

  /// Process a PATH_RESPONSE frame.
  ///
  /// Returns `true` if the response data matches a pending challenge.
  /// On match, the challenge is removed from pending and the path is
  /// marked as validated.
  bool onResponseReceived(PathResponseFrame frame) {
    final data = frame.data;
    if (!_pendingChallenges.containsKey(data)) {
      return false;
    }
    _pendingChallenges.remove(data);
    // SECURITY: Evict oldest validated path if at capacity.
    if (_validatedPaths.length >= maxValidatedPaths) {
      _validatedPaths.remove(_validatedPaths.first);
    }
    _validatedPaths.add(_bytesToHex(data));
    return true;
  }

  /// Check if any challenges have timed out.
  ///
  /// Returns the challenge data for entries older than [timeoutUs].
  /// Expired entries are removed from pending.
  List<List<int>> getExpiredChallenges(int currentTimeUs,
      {int timeoutUs = defaultTimeoutUs}) {
    final expired = <List<int>>[];
    _pendingChallenges.removeWhere((data, sentTime) {
      // SECURITY: Guard against clock backward jumps.
      if (currentTimeUs >= sentTime && currentTimeUs - sentTime > timeoutUs) {
        expired.add(data);
        return true;
      }
      return false;
    });
    return expired;
  }

  /// Check if a path is validated.
  ///
  /// A path is considered validated if its challenge data has received
  /// a matching PATH_RESPONSE.
  bool isPathValidated(List<int> pathId) {
    return _validatedPaths.contains(_bytesToHex(pathId));
  }

  /// Reset all state.
  void reset() {
    _pendingChallenges.clear();
    _validatedPaths.clear();
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  /// Evict the oldest pending challenge (lowest timestamp).
  void _evictOldestChallenge() {
    var oldestKey = _pendingChallenges.keys.first;
    var oldestTime = _pendingChallenges[oldestKey]!;
    for (final entry in _pendingChallenges.entries) {
      if (entry.value < oldestTime) {
        oldestTime = entry.value;
        oldestKey = entry.key;
      }
    }
    _pendingChallenges.remove(oldestKey);
  }

  static int _nowUs() {
    return DateTime.now().microsecondsSinceEpoch;
  }

  static String _bytesToHex(List<int> bytes) {
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

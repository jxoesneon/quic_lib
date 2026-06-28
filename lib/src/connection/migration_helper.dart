import 'dart:math';
import 'dart:typed_data';

import 'package:quic_lib/src/utils/hex.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Helper for QUIC connection path validation via PATH_CHALLENGE / PATH_RESPONSE.
///
/// RFC 9000 Section 8.2: A path is considered validated when a PATH_RESPONSE
/// frame is received that echoes the data sent in a PATH_CHALLENGE frame.
class MigrationHelper {
  // SECURITY: Limits to prevent memory exhaustion DoS.
  static const int maxPendingChallenges = 8;
  static const int maxValidatedPaths = 16;

  /// Active path challenges: hex(challenge_data) → sent_time_us.
  final Map<String, int> _pendingChallenges = {};

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
    final data =
        Uint8List.fromList(List<int>.generate(8, (_) => random.nextInt(256)));
    _pendingChallenges[bytesToHex(data)] = currentTimeUs ?? _nowUs();
    return PathChallengeFrame(data: data);
  }

  /// Process a PATH_RESPONSE frame.
  ///
  /// Returns `true` if the response data matches a pending challenge.
  /// On match, the challenge is removed from pending and the path is
  /// marked as validated.
  bool onResponseReceived(PathResponseFrame frame) {
    final key = bytesToHex(frame.data);
    if (!_pendingChallenges.containsKey(key)) {
      return false;
    }
    _pendingChallenges.remove(key);
    // SECURITY: Evict oldest validated path if at capacity.
    if (_validatedPaths.length >= maxValidatedPaths) {
      _validatedPaths.remove(_validatedPaths.first);
    }
    _validatedPaths.add(key);
    return true;
  }

  /// Check if any challenges have timed out.
  ///
  /// Returns the challenge data for entries older than [timeoutUs].
  /// Expired entries are removed from pending.
  List<Uint8List> getExpiredChallenges(int currentTimeUs,
      {int timeoutUs = defaultTimeoutUs}) {
    final expired = <Uint8List>[];
    _pendingChallenges.removeWhere((key, sentTime) {
      // SECURITY: Guard against clock backward jumps.
      if (currentTimeUs >= sentTime && currentTimeUs - sentTime > timeoutUs) {
        expired.add(hexToBytes(key));
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
    return _validatedPaths.contains(bytesToHex(pathId));
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
}

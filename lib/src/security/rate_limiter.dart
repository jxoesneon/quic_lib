/// Simple sliding-window rate limiter for defensive hardening.
///
/// Tracks the number of calls within a time window and rejects
/// calls that would exceed the configured maximum.
class RateLimiter {
  final int maxCalls;
  final int windowMs;

  final List<int> _timestamps = [];

  RateLimiter({required this.maxCalls, required this.windowMs})
      : assert(maxCalls > 0),
        assert(windowMs > 0);

  /// Check if a call is permitted at [nowMs].
  ///
  /// Returns `true` if the call is within the rate limit,
  /// `false` if it should be rejected.
  bool check(int nowMs) {
    _prune(nowMs);
    if (_timestamps.length >= maxCalls) {
      return false;
    }
    _timestamps.add(nowMs);
    return true;
  }

  /// Same as [check] but throws [StateError] on rejection.
  void checkOrThrow(int nowMs, {String? label}) {
    if (!check(nowMs)) {
      throw StateError(
        label != null
            ? 'Rate limit exceeded for $label ($maxCalls/$windowMs ms)'
            : 'Rate limit exceeded ($maxCalls/$windowMs ms)',
      );
    }
  }

  /// Current number of tracked calls in the window.
  int get currentCount => _timestamps.length;

  /// Reset all tracked state.
  void reset() => _timestamps.clear();

  void _prune(int nowMs) {
    final cutoff = nowMs - windowMs;
    _timestamps.removeWhere((t) => t < cutoff);
  }
}

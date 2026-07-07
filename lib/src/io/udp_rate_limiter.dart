import 'dart:io';

/// Per-source IP rate limiter for incoming UDP datagrams.
///
/// Tracks the arrival timestamps of datagrams from each source IP inside a
/// sliding [rateLimitWindowMs] window. A source that sends more than
/// [maxDatagramsPerIpPerSecond] datagrams within the window is rate-limited
/// and subsequent datagrams should be dropped by the caller.
///
/// To protect against memory exhaustion from spoofed sources, the number of
/// tracked IPs is capped at [maxTrackedIps]. When the cap is reached and a
/// datagram arrives from a new source, the oldest tracked source is evicted.
class UdpRateLimiter {
  static const int _defaultMaxDatagramsPerIpPerSecond = 1000;
  static const int _defaultRateLimitWindowMs = 1000;
  static const int _defaultMaxTrackedIps = 10000;

  /// Maximum number of datagrams allowed per source IP per window.
  final int maxDatagramsPerIpPerSecond;

  /// Sliding window length, in milliseconds.
  final int rateLimitWindowMs;

  /// Maximum number of distinct source IPs to retain timestamp data for.
  final int maxTrackedIps;

  final int Function() _clock;

  /// Per-source IP rate tracking: ip_string to list of timestamp_ms values.
  final Map<String, List<int>> _ipTimestamps;

  /// Creates a new rate limiter.
  ///
  /// [clock] is injected for testing so that time can be controlled without
  /// relying on real wall-clock delays.
  UdpRateLimiter({
    this.maxDatagramsPerIpPerSecond = _defaultMaxDatagramsPerIpPerSecond,
    this.rateLimitWindowMs = _defaultRateLimitWindowMs,
    this.maxTrackedIps = _defaultMaxTrackedIps,
    int Function()? clock,
  })  : _clock = clock ?? _defaultClock,
        _ipTimestamps = {};

  static int _defaultClock() => DateTime.now().millisecondsSinceEpoch;

  /// DEBUG: expose internal state for test diagnostics.
  Map<String, List<int>> get debugTimestamps => _ipTimestamps;

  /// Returns `true` if a datagram from [address] should be accepted.
  ///
  /// Returns `false` when the source has exceeded the per-second allowance
  /// within the current window. When the tracked-IP cap is reached and the
  /// source is new, the oldest tracked source is evicted first.
  bool isAllowed(InternetAddress address) {
    final now = _clock();
    final ipKey = address.address;

    // SECURITY: Evict oldest tracked IP if at capacity.
    if (_ipTimestamps.length >= maxTrackedIps &&
        !_ipTimestamps.containsKey(ipKey)) {
      _evictOldestIp();
    }

    final timestamps = _ipTimestamps.putIfAbsent(ipKey, () => []);
    // Prune old timestamps outside the window.
    final cutoff = now - rateLimitWindowMs;
    timestamps.removeWhere((t) => t < cutoff);
    if (timestamps.length >= maxDatagramsPerIpPerSecond) {
      return false;
    }
    timestamps.add(now);
    return true;
  }

  /// Removes the tracked source with the oldest last-seen timestamp.
  ///
  /// An empty timestamp list is treated as the oldest possible time (zero).
  /// If the table is empty this method is a no-op.
  void _evictOldestIp() {
    String? oldestKey;
    int? oldestTime;
    for (final entry in _ipTimestamps.entries) {
      final newest = entry.value.isEmpty ? 0 : entry.value.last;
      if (oldestTime == null || newest < oldestTime) {
        oldestTime = newest;
        oldestKey = entry.key;
      }
    }
    if (oldestKey != null) {
      _ipTimestamps.remove(oldestKey);
    }
  }
}

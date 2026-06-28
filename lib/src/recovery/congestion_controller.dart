import 'package:quic_lib/src/connection/congestion_control/congestion_controller.dart'
    as cc;
import 'package:quic_lib/src/connection/congestion_control/hystart.dart';

/// NewReno congestion controller per RFC 9002 Section 7.
///
/// Implements slow start, congestion avoidance, and recovery.
class CongestionController implements cc.CongestionController {
  /// Initial congestion window in bytes (RFC 9002: 2 * max_datagram_size, default 1200).
  static const int initialWindow = 2400;

  /// Minimum congestion window in bytes.
  static const int minimumWindow = 2400;

  static const int _maxDatagramSize = 1200;

  int _congestionWindow = initialWindow;
  int _ssthresh = -1; // -1 means no threshold (always in slow start).
  int _bytesInFlight = 0;
  int _congestionRecoveryStartTime = -1; // -1 means not in recovery.
  bool _appLimited = false;
  final Hystart _hystart = Hystart();

  /// Current congestion window in bytes.
  @override
  int get congestionWindow => _congestionWindow;

  /// Slow start threshold. -1 means no threshold (always in slow start).
  int get ssthresh => _ssthresh;

  /// Whether in slow start.
  bool get inSlowStart => _ssthresh < 0 || _congestionWindow < _ssthresh;

  /// Whether in recovery.
  bool get inRecovery => _congestionRecoveryStartTime >= 0;

  /// Bytes in flight.
  @override
  int get bytesInFlight => _bytesInFlight;

  /// Whether the application is currently limited.
  @override
  bool get appLimited => _appLimited;

  /// Set the application-limited state.
  @override
  void setAppLimited(bool limited) {
    _appLimited = limited;
  }

  /// Register a packet as sent (adds to bytes_in_flight).
  ///
  /// Callers MUST only account in-flight packets (those containing ack-eliciting
  /// frames). Per RFC 9000 Errata 8240, CONNECTION_CLOSE frames do not count.
  @override
  void onPacketSent(int packetNumber, int size) {
    // SECURITY: Reject negative byte counts.
    if (size < 0) size = 0;
    _bytesInFlight += size;
    // Exit app-limited when cwnd is fully utilized.
    if (_bytesInFlight >= _congestionWindow) {
      _appLimited = false;
    }
  }

  /// Process an ACK.
  @override
  void onAckReceived(int largestAcked, int newlyAckedBytes, DateTime now) {
    // SECURITY: Reject negative ackedBytes to prevent integer underflow.
    if (newlyAckedBytes < 0) newlyAckedBytes = 0;

    // Remove acknowledged bytes from bytes in flight.
    _bytesInFlight -= newlyAckedBytes;
    if (_bytesInFlight < 0) {
      _bytesInFlight = 0;
    }

    // Do not increase cwnd during recovery or when app-limited.
    if (inRecovery || _appLimited) {
      return;
    }

    // Hystart: check for early slow-start exit.
    if (inSlowStart) {
      _hystart.onAck(largestAcked, now);
      if (_hystart.shouldExitSlowStart) {
        _ssthresh = _congestionWindow;
      }
    }

    // SECURITY: Cap cwnd growth to prevent 64-bit integer overflow.
    const maxCwnd = 0x3FFFFFFFFFFFFFFF;
    if (inSlowStart) {
      // Slow start: cwnd += acked_bytes.
      if (_congestionWindow > maxCwnd - newlyAckedBytes) {
        _congestionWindow = maxCwnd;
      } else {
        _congestionWindow += newlyAckedBytes;
      }
    } else {
      // Congestion avoidance: cwnd += max_datagram_size * acked_bytes / cwnd.
      final growth = (_maxDatagramSize * newlyAckedBytes) ~/ _congestionWindow;
      if (_congestionWindow > maxCwnd - growth) {
        _congestionWindow = maxCwnd;
      } else {
        _congestionWindow += growth;
      }
    }
  }

  /// Enter recovery (on loss detection).
  @override
  void onPacketLost(int packetNumber, int lostBytes, DateTime now) {
    if (inRecovery) {
      // Already in recovery; do not reduce cwnd again until exit.
      return;
    }
    _congestionRecoveryStartTime = now.millisecondsSinceEpoch;
    _ssthresh = _congestionWindow ~/ 2;
    _congestionWindow = _ssthresh > minimumWindow ? _ssthresh : minimumWindow;
    _bytesInFlight -= lostBytes;
    if (_bytesInFlight < 0) {
      _bytesInFlight = 0;
    }
  }

  /// Exit recovery (RFC 9002 §7.3.2).
  void onRecoveryExit() {
    _congestionRecoveryStartTime = -1;
  }

  /// Record an RTT sample.
  @override
  void onRttSample(Duration rtt) {
    // NewReno does not directly use RTT samples for cwnd.
  }

  /// React to ECN Congestion Experienced (CE) marks.
  ///
  /// Per RFC 9002 Section 7.3.3, reduces the congestion window as though
  /// a loss was detected.
  @override
  void onECNCEMarked(int count) {
    final now = DateTime.now();
    // ECN CE marks don't specify exact lost bytes; treat as a single
    // packet loss for cwnd reduction purposes.
    onPacketLost(0, _maxDatagramSize, now);
  }

  /// Persistent congestion declared (RFC 9002 §7.6).
  ///
  /// Reduces cwnd to the minimum congestion window without clearing
  /// bytes in flight.
  @override
  void onPersistentCongestion() {
    _congestionWindow = minimumWindow;
  }

  /// Can we send [bytes]?
  @override
  bool canSend(int bytes) {
    return _bytesInFlight + bytes <= _congestionWindow;
  }

  /// Reset to initial state.
  @override
  void reset() {
    _congestionWindow = initialWindow;
    _ssthresh = -1;
    _bytesInFlight = 0;
    _congestionRecoveryStartTime = -1;
    _appLimited = false;
    _hystart.reset();
  }
}

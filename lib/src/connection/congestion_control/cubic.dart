import 'dart:math';

import 'congestion_controller.dart';
import 'hystart.dart';

/// RFC 8312 / RFC 9002 CUBIC congestion controller.
///
/// CUBIC uses a cubic function of elapsed time since last loss to grow cwnd:
///   W_cubic(t) = C*(t - K)^3 + W_max
/// where K = cubic_root(W_max * (1 - β_cubic) / C)
/// and β_cubic = 0.7 (multiplicative decrease factor)
///
/// C is the CUBIC scaling factor (default 0.4).
class CubicCongestionController implements CongestionController {
  static const double _cubicScalingFactor = 0.4; // C
  static const double _betaCubic = 0.7; // β_cubic
  static const int _minCwndPackets = 2; // Minimum cwnd in packets (RFC 9002)

  int _cwnd = 2; // Internal cwnd in packets
  int _ssthresh = double.maxFinite.toInt(); // Slow start threshold (infinity)
  int _wMax = 0; // Window size just before last reduction (packets)
  DateTime? _congestionEventTime; // Time of last congestion event
  final int _packetSize; // max_datagram_size
  int _bytesInFlight = 0;
  bool _inFastRecovery = false;
  int _recoveryStartPacket = 0;
  int _smoothedRttUs = 1000000; // Default 1s until first RTT sample
  bool _appLimited = false;
  final Hystart _hystart = Hystart();

  CubicCongestionController({int initialCwnd = 2, int packetSize = 1200})
      : _cwnd = initialCwnd,
        _packetSize = packetSize;

  /// Current cwnd in packets (exposed for testing).
  int get cwndInPackets => _cwnd;

  /// W_max in packets (exposed for testing fast convergence).
  int get wMax => _wMax;

  @override
  int get congestionWindow => _cwnd * _packetSize;

  @override
  int get bytesInFlight => _bytesInFlight;

  @override
  bool get appLimited => _appLimited;

  @override
  void setAppLimited(bool limited) {
    _appLimited = limited;
  }

  @override
  void onPacketSent(int packetNumber, int size) {
    _bytesInFlight += size;
    // Exit app-limited when cwnd is fully utilized.
    if (_bytesInFlight >= _cwnd * _packetSize) {
      _appLimited = false;
    }
  }

  @override
  void onAckReceived(int largestAcked, int newlyAckedBytes, DateTime now) {
    if (_inFastRecovery) {
      if (largestAcked > _recoveryStartPacket) {
        _inFastRecovery = false;
      } else {
        // In fast recovery, deflate cwnd by acked bytes
        _cwnd = max(_cwnd - newlyAckedBytes ~/ _packetSize, _minCwndPackets);
        _bytesInFlight = max(0, _bytesInFlight - newlyAckedBytes);
        return;
      }
    }

    // Do not grow cwnd when app-limited.
    if (_appLimited) {
      _bytesInFlight = max(0, _bytesInFlight - newlyAckedBytes);
      return;
    }

    if (_cwnd < _ssthresh) {
      // Slow start: cwnd += newly acked packets
      _hystart.onAck(largestAcked, now);
      if (_hystart.shouldExitSlowStart) {
        _ssthresh = _cwnd;
      }
      _cwnd += newlyAckedBytes ~/ _packetSize;
    } else {
      // Congestion avoidance: CUBIC algorithm
      _cwnd = _cubicCwnd(now);
    }
    _bytesInFlight = max(0, _bytesInFlight - newlyAckedBytes);
  }

  @override
  void onPacketLost(int packetNumber, int lostBytes, DateTime now) {
    if (_inFastRecovery && packetNumber <= _recoveryStartPacket) {
      // Already in recovery for this loss
      return;
    }

    _inFastRecovery = true;
    _recoveryStartPacket = packetNumber;

    final wLastMax = _wMax;
    _wMax = _cwnd;

    if (_wMax < wLastMax) {
      // Fast convergence
      _wMax = (_wMax * (1 + _betaCubic) / 2).floor();
    }

    _ssthresh = max((_cwnd * _betaCubic).floor(), _minCwndPackets);
    _cwnd = _ssthresh;
    _congestionEventTime = now;
    _bytesInFlight = max(0, _bytesInFlight - lostBytes);
  }

  @override
  void onRttSample(Duration rtt) {
    _smoothedRttUs = rtt.inMicroseconds;
  }

  @override
  void onECNCEMarked(int count) {
    // RFC 9002 Section 7.3.3: Reduce cwnd as though a loss was detected.
    // Estimate lost bytes as one packet since ECN CE marks don't indicate
    // exact lost bytes.
    final now = DateTime.now();
    onPacketLost(_recoveryStartPacket + 1, _packetSize, now);
  }

  @override
  void onPersistentCongestion() {
    _cwnd = _minCwndPackets;
  }

  @override
  bool canSend(int bytes) {
    return _bytesInFlight + bytes <= _cwnd * _packetSize;
  }

  int _cubicCwnd(DateTime now) {
    if (_congestionEventTime == null) {
      return _cwnd;
    }

    final t =
        now.difference(_congestionEventTime!).inMicroseconds / 1e6; // seconds
    final k = _cubicK();
    final wCubic = _cubicScalingFactor * pow(t - k, 3) + _wMax;

    // TCP-friendly region (RFC 8312 Equation 2)
    // W_est(t) = W_max * beta + (3 * (1 - beta) / (1 + beta)) * (t / RTT)
    final rttSeconds = _smoothedRttUs / 1e6;
    final tOverRtt = rttSeconds > 0 ? t / rttSeconds : t;
    final wEst = _wMax * _betaCubic +
        (3 * (1 - _betaCubic) / (1 + _betaCubic)) * tOverRtt;

    final target = wCubic > wEst ? wCubic : wEst;
    return max(target.floor(), _minCwndPackets);
  }

  double _cubicK() {
    if (_wMax == 0) return 0;
    return pow(_wMax * (1 - _betaCubic) / _cubicScalingFactor, 1.0 / 3.0)
        .toDouble();
  }

  @override
  void reset() {
    _cwnd = 2;
    _ssthresh = double.maxFinite.toInt();
    _wMax = 0;
    _congestionEventTime = null;
    _bytesInFlight = 0;
    _inFastRecovery = false;
    _appLimited = false;
    _hystart.reset();
  }
}

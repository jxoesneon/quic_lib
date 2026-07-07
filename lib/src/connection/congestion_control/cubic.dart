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

  /// Marks whether the sender is application-limited.
  ///
  /// When [limited] is `true`, [onAckReceived] will not grow the congestion
  /// window even if acks arrive, because the window is not the bottleneck.
  /// This prevents CUBIC from inflating the window during idle periods and
  /// producing a misleadingly large burst once the application resumes sending.
  ///
  /// [limited] is reset to `false` automatically by [onPacketSent] once
  /// the bytes in flight fill the current window.
  @override
  void setAppLimited(bool limited) {
    _appLimited = limited;
  }

  /// Records a sent packet and updates bytes-in-flight.
  ///
  /// [packetNumber] is used to identify when fast-recovery for an earlier
  /// loss event can be exited (packets sent after the loss are new). [size]
  /// is the wire-format byte length of the packet including QUIC headers.
  ///
  /// If bytes-in-flight now fills the entire congestion window, the
  /// app-limited flag is cleared so window growth can resume on the next ACK.
  @override
  void onPacketSent(int packetNumber, int size) {
    _bytesInFlight += size;
    // Exit app-limited when cwnd is fully utilized.
    if (_bytesInFlight >= _cwnd * _packetSize) {
      _appLimited = false;
    }
  }

  /// Processes an incoming ACK and grows the congestion window.
  ///
  /// The window growth follows three regimes:
  /// 1. **Fast recovery**: deflate cwnd by the number of newly acked packets
  ///    until recovery is exited when [largestAcked] surpasses the recovery
  ///    start packet number.
  /// 2. **Slow start** (cwnd < ssthresh): increase cwnd by the number of
  ///    newly acked packets; Hystart++ exit check is applied.
  /// 3. **Congestion avoidance** (cwnd ≥ ssthresh): apply the CUBIC
  ///    W_cubic(t) formula (RFC 8312 §5).
  ///
  /// [largestAcked] is the highest packet number confirmed by the ACK frame.
  /// [newlyAckedBytes] is the total byte count of newly acknowledged packets.
  /// [now] is the current wall-clock time used for the CUBIC time calculation.
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

  /// Records a packet loss event and reduces the congestion window.
  ///
  /// On the first loss in a new round (i.e., [packetNumber] is not already
  /// inside the current fast-recovery window), CUBIC applies:
  /// - **Fast convergence**: if the new W_max is smaller than the previous
  ///   W_max, it is further reduced to accelerate convergence among competing
  ///   flows (RFC 8312 §4.6).
  /// - **Multiplicative decrease**: ssthresh = max(cwnd × β_cubic, 2 packets).
  ///   cwnd is set to ssthresh and fast recovery begins.
  ///
  /// Subsequent losses within the same recovery window are ignored.
  ///
  /// [packetNumber] identifies the lost packet for recovery-window tracking.
  /// [lostBytes] is the wire-format byte size of the lost packet.
  /// [now] is the timestamp used to anchor the CUBIC W_cubic(t) calculation.
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

  /// Updates the smoothed RTT used by the CUBIC TCP-friendly calculation.
  ///
  /// CUBIC's TCP-friendly region (RFC 8312 §5.1) requires the RTT to compute
  /// the window size that standard TCP would achieve. [rtt] is typically the
  /// latest smoothed RTT from the [RttEstimator].
  @override
  void onRttSample(Duration rtt) {
    _smoothedRttUs = rtt.inMicroseconds;
  }

  /// Reduces the congestion window in response to ECN Congestion Experienced marks.
  ///
  /// Per RFC 9002 Section 7.3.3, an ECN CE mark is treated the same as a
  /// detected loss: [onPacketLost] is called with an estimated one-packet
  /// loss to trigger the CUBIC multiplicative decrease.
  ///
  /// [count] is the number of newly CE-marked packets reported in the
  /// ACK_ECN frame (currently treated as a single loss event regardless of
  /// the count to avoid over-reacting).
  @override
  void onECNCEMarked(int count) {
    // RFC 9002 Section 7.3.3: Reduce cwnd as though a loss was detected.
    // Estimate lost bytes as one packet since ECN CE marks don't indicate
    // exact lost bytes.
    final now = DateTime.now();
    onPacketLost(_recoveryStartPacket + 1, _packetSize, now);
  }

  /// Collapses the congestion window on persistent congestion (RFC 9002 §7.6).
  ///
  /// When the loss detector determines that all in-flight packets over a
  /// multi-PTO time window have been lost, the network is deemed persistently
  /// congested. CUBIC responds by dropping the window to the absolute minimum
  /// (`_minCwndPackets = 2`) and discarding the slow-start threshold so that
  /// the connection effectively restarts slow start from scratch.
  @override
  void onPersistentCongestion() {
    _cwnd = _minCwndPackets;
  }

  /// Returns `true` if [bytes] can be sent without exceeding the congestion window.
  ///
  /// Compares `bytesInFlight + bytes` against `cwnd × maxDatagramSize`. This
  /// is the primary pacing gate: when it returns `false` the sender must wait
  /// for ACKs to reduce [bytesInFlight] before transmitting more data.
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

  /// Resets CUBIC state to the initial condition.
  ///
  /// Clears the congestion window, slow-start threshold, W_max, fast-recovery
  /// flag, bytes-in-flight, app-limited flag, and the Hystart++ detector.
  /// After a reset the controller behaves as if the connection had just been
  /// established and will begin a fresh slow-start phase.
  ///
  /// Typically called after a connection migration or a catastrophic loss event.
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

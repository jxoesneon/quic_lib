import 'dart:math';

import 'congestion_controller.dart';

/// BBR (Bottleneck Bandwidth and Round-trip propagation time)
/// congestion controller per RFC 8382.
///
/// BBR is a model-based congestion controller that estimates the bottleneck
/// bandwidth and minimum RTT to compute a pacing rate and congestion window.
/// Unlike loss-based controllers (NewReno/CUBIC), BBR does not rely on packet
/// loss to signal congestion and therefore performs better on paths with
/// shallow buffers or stochastic loss.
///
/// Key state machine:
/// - **STARTUP**: rapid bandwidth discovery (pacing_gain = 2.77)
/// - **DRAIN**: drain queue built during STARTUP (pacing_gain = 0.35)
/// - **PROBE_BW**: cycle through bandwidth probing phases
/// - **PROBE_RTT**: periodically drain to 4 packets to refresh RTprop
class BbrCongestionController implements CongestionController {
  // ---------------------------------------------------------------------------
  // RFC 8382 constants
  // ---------------------------------------------------------------------------
  static const double _bbrHighGain = 2.89; // STARTUP pacing gain
  static const double _bbrDrainGain = 1.0 / _bbrHighGain; // DRAIN pacing gain
  static const double _bbrPacingGain = 1.0; // steady-state pacing gain
  static const double _bbrCwndGain = 2.0; // cwnd gain factor
  static const double _bbrMinCwndGain = 2.0; // minimum cwnd during STARTUP
  static const int _bbrProbeRttDurationUs = 200000; // 200 ms PROBE_RTT duration
  static const int _bbrProbeRttIntervalUs = 10000000; // 10 s between PROBE_RTT
  static const int _bbrMinCwndPackets = 4; // minimum cwnd in PROBE_RTT
  static const int _startupRoundsThreshold =
      3; // rounds without bw growth to exit STARTUP
  static const double _bwGrowthThreshold =
      1.25; // bw must grow by 25% per round in STARTUP

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  int _cwnd = 4; // current cwnd in packets
  final int _packetSize; // max_datagram_size in bytes
  int _bytesInFlight = 0;
  int _minRttUs = -1; // RTprop: minimum RTT observed
  DateTime? _minRttTimestamp;

  // Bandwidth filter: keep max over 10 RTT window.
  final List<_BwSample> _bwFilter = [];
  static const int _bwWindowRtts = 10;
  double _btlBw = 0; // bottleneck bandwidth in bytes per second

  // State machine.
  BbrState _state = BbrState.startup;
  int _roundCounter = 0;
  int _roundStart = -1;
  int _startupRoundsWithoutGrowth = 0;
  double _lastBtlBw = 0;

  // PROBE_RTT
  int _probeRttDoneTimeUs = -1;
  bool _probeRttRoundDone = false;

  // Pacing
  int _pacingIntervalUs = 0;

  // Delivery tracking for bandwidth estimation.
  int _delivered = 0;

  BbrCongestionController({int packetSize = 1200}) : _packetSize = packetSize;

  // ---------------------------------------------------------------------------
  // CongestionController interface
  // ---------------------------------------------------------------------------
  @override
  int get congestionWindow => _cwnd * _packetSize;

  @override
  int get bytesInFlight => _bytesInFlight;

  /// Records a sent packet and updates bytes-in-flight.
  ///
  /// [packetNumber] is used as the round-trip boundary marker: when an ACK
  /// for a packet number ≥ [packetNumber] arrives, the current bandwidth-
  /// estimation round is considered complete.
  ///
  /// [size] is the wire-format byte length of the sent packet including
  /// headers and QUIC overhead.
  @override
  void onPacketSent(int packetNumber, int size) {
    _bytesInFlight += size;
    _roundStart = packetNumber;
  }

  /// Processes an incoming ACK and advances the BBR state machine.
  ///
  /// This method:
  /// 1. Reduces [bytesInFlight] by [newlyAckedBytes].
  /// 2. Updates the bandwidth filter (bottleneck bandwidth estimate).
  /// 3. Advances the round counter when [largestAcked] ≥ the round-start marker.
  /// 4. Checks for STARTUP → DRAIN → PROBE_BW → PROBE_RTT state transitions.
  /// 5. Recomputes the congestion window and pacing interval.
  ///
  /// [largestAcked] is the highest packet number confirmed by the ACK frame.
  /// [newlyAckedBytes] is the total byte count of newly acknowledged packets.
  /// [now] is the current wall-clock time used for RTprop and pacing updates.
  @override
  void onAckReceived(int largestAcked, int newlyAckedBytes, DateTime now) {
    _bytesInFlight = max(0, _bytesInFlight - newlyAckedBytes);

    // Update RTprop.
    if (_minRttUs < 0) {
      _minRttUs = 200000; // Default 200ms until first sample.
      _minRttTimestamp = now;
    }

    // Update delivery rate for bandwidth estimation.
    _delivered += newlyAckedBytes;
    _updateBwFilter(now);

    // Update bottleneck bandwidth.
    final newBtlBw =
        _bwFilter.isEmpty ? _btlBw : _bwFilter.map((s) => s.bw).reduce(max);
    if (newBtlBw > _btlBw) {
      _btlBw = newBtlBw;
    }

    // Check for round completion.
    if (largestAcked >= _roundStart) {
      _roundCounter++;
      _checkStartupExit(now);
      _checkDrainDone();
      _checkProbeRttDone(now);
    }

    // Update state machine.
    _updateStateMachine(now);

    // Update cwnd.
    _updateCwnd();

    // Update pacing.
    _updatePacing(now);
  }

  /// Records a packet loss event.
  ///
  /// BBR v1 does not treat individual packet loss as a congestion signal —
  /// the bandwidth filter naturally converges to a lower value when packets
  /// are lost. This method only updates [bytesInFlight]; no window reduction
  /// is performed. BBR v2 (not yet implemented) would apply additional logic
  /// here per the draft RFC.
  ///
  /// [packetNumber] identifies the lost packet (unused in v1).
  /// [lostBytes] is the wire-format byte size of the lost packet.
  /// [now] is the current wall-clock time (unused in v1).
  @override
  void onPacketLost(int packetNumber, int lostBytes, DateTime now) {
    _bytesInFlight = max(0, _bytesInFlight - lostBytes);
    // BBR does not react to individual loss events.
    // Loss handling is implicit via bandwidth estimation.
  }

  /// Updates the minimum RTT estimate (RTprop) with a new sample.
  ///
  /// BBR tracks RTprop as the minimum RTT observed over a 10-second window
  /// (the `ProbeRTT` interval). A lower RTprop triggers the PROBE_RTT state
  /// which drains the queue to re-measure the true propagation delay.
  ///
  /// [rtt] is the latest round-trip time sample, typically derived from the
  /// [RttEstimator].
  @override
  void onRttSample(Duration rtt) {
    final rttUs = rtt.inMicroseconds;
    if (_minRttUs < 0 || rttUs < _minRttUs) {
      _minRttUs = rttUs;
      _minRttTimestamp = DateTime.now();
    }
  }

  /// Notifies the controller that [count] packets were ECN CE-marked.
  ///
  /// BBR v1 ignores ECN Congestion Experienced (CE) marks because it derives
  /// its congestion signal from bandwidth estimation rather than loss or
  /// explicit marking. This method is a no-op for BBR v1.
  ///
  /// BBR v2 (draft RFC) would reduce the pacing rate on CE marks; that
  /// behavior is not yet implemented.
  @override
  void onECNCEMarked(int count) {
    // BBR v1 does not use ECN. BBR v2 may incorporate ECN signals.
    // For now, treat as no-op per RFC 8382.
  }

  /// Returns `true` if [bytes] can be sent without exceeding the congestion window.
  ///
  /// Checks that `bytesInFlight + bytes ≤ cwnd`. This is the primary back-
  /// pressure signal: when [canSend] returns `false` the sender must pause
  /// until ACKs reduce [bytesInFlight].
  @override
  bool canSend(int bytes) {
    return _bytesInFlight + bytes <= _cwnd * _packetSize;
  }

  /// Resets all BBR state to the initial STARTUP condition.
  ///
  /// Clears the congestion window, bytes-in-flight, bandwidth filter,
  /// RTprop estimate, round counters, and pacing interval. The controller
  /// restarts in the [BbrState.startup] phase as if the connection had just
  /// been established.
  ///
  /// This is typically called after a connection migration or when the
  /// recovery subsystem needs to reset congestion state.
  @override
  void reset() {
    _cwnd = 4;
    _bytesInFlight = 0;
    _minRttUs = -1;
    _minRttTimestamp = null;
    _bwFilter.clear();
    _btlBw = 0;
    _state = BbrState.startup;
    _roundCounter = 0;
    _roundStart = -1;
    _startupRoundsWithoutGrowth = 0;
    _lastBtlBw = 0;
    _probeRttDoneTimeUs = -1;
    _probeRttRoundDone = false;
    _pacingIntervalUs = 0;
    _delivered = 0;
  }

  @override
  bool get appLimited => false;

  /// Marks whether the sender is application-limited.
  ///
  /// BBR v1 tracks application-limited periods implicitly through the delivery
  /// rate calculation: when the application does not fully utilize the
  /// congestion window the bandwidth samples are naturally lower. There is no
  /// explicit state to toggle, so this method is a no-op for BBR v1.
  ///
  /// [limited] is `true` when the application cannot produce data fast enough
  /// to fill the congestion window, and `false` otherwise.
  @override
  void setAppLimited(bool limited) {
    // BBR tracks app-limited implicitly via delivery rate.
    // No explicit state needed for v1.
  }

  /// Handles a persistent congestion event (RFC 9002 Section 7.6).
  ///
  /// When the loss detector determines that the network is persistently
  /// congested (i.e., all in-flight packets over a multi-PTO window are
  /// lost), the congestion window is collapsed to the minimum of
  /// `_bbrMinCwndPackets` and the state machine is reset to STARTUP so that
  /// BBR can rediscover the available bandwidth.
  @override
  void onPersistentCongestion() {
    // BBR handles persistent congestion by bandwidth estimation.
    // Reset cwnd to minimum.
    _cwnd = _bbrMinCwndPackets;
    _state = BbrState.startup;
  }

  // ---------------------------------------------------------------------------
  // State machine helpers
  // ---------------------------------------------------------------------------
  void _updateStateMachine(DateTime now) {
    switch (_state) {
      case BbrState.startup:
        // Exit handled in _checkStartupExit.
        break;
      case BbrState.drain:
        // Exit handled in _checkDrainDone.
        break;
      case BbrState.probeBw:
        _maybeEnterProbeRtt(now);
        break;
      case BbrState.probeRtt:
        // Exit handled in _checkProbeRttDone.
        break;
    }
  }

  void _checkStartupExit(DateTime now) {
    if (_state != BbrState.startup) return;

    if (_btlBw >= _lastBtlBw * _bwGrowthThreshold) {
      _startupRoundsWithoutGrowth = 0;
    } else {
      _startupRoundsWithoutGrowth++;
    }
    _lastBtlBw = _btlBw;

    if (_startupRoundsWithoutGrowth >= _startupRoundsThreshold) {
      _state = BbrState.drain;
    }
  }

  void _checkDrainDone() {
    if (_state != BbrState.drain) return;
    if (_bytesInFlight <= _btlBw * _minRttUs / 1e6) {
      _state = BbrState.probeBw;
    }
  }

  void _maybeEnterProbeRtt(DateTime now) {
    if (_minRttTimestamp == null) return;
    final elapsedUs =
        now.difference(_minRttTimestamp!).inMicroseconds + _minRttUs;
    if (elapsedUs > _bbrProbeRttIntervalUs) {
      _state = BbrState.probeRtt;
      _probeRttDoneTimeUs = now.microsecondsSinceEpoch + _bbrProbeRttDurationUs;
      _probeRttRoundDone = false;
    }
  }

  void _checkProbeRttDone(DateTime now) {
    if (_state != BbrState.probeRtt) return;

    if (!_probeRttRoundDone && _roundCounter > 0) {
      _probeRttRoundDone = true;
    }

    final nowUs = now.microsecondsSinceEpoch;
    if (_probeRttRoundDone && nowUs >= _probeRttDoneTimeUs) {
      _minRttTimestamp = now;
      _state = BbrState.probeBw;
    }
  }

  // ---------------------------------------------------------------------------
  // Cwnd and pacing
  // ---------------------------------------------------------------------------
  void _updateCwnd() {
    double gain;
    switch (_state) {
      case BbrState.startup:
        gain = _bbrHighGain;
        break;
      case BbrState.drain:
        gain = _bbrDrainGain;
        break;
      case BbrState.probeBw:
        gain = _bbrCwndGain;
        break;
      case BbrState.probeRtt:
        gain = _bbrMinCwndGain;
        break;
    }

    if (_state == BbrState.probeRtt) {
      _cwnd = max(_bbrMinCwndPackets, _cwnd);
      return;
    }

    final target = _btlBw * _minRttUs / 1e6 * gain;
    _cwnd = max(target ~/ _packetSize, _bbrMinCwndPackets);
  }

  void _updatePacing(DateTime now) {
    double gain;
    switch (_state) {
      case BbrState.startup:
        gain = _bbrHighGain;
        break;
      case BbrState.drain:
        gain = _bbrDrainGain;
        break;
      case BbrState.probeBw:
        // Cycle through [1.25, 0.75, 1, 1, 1, 1, 1, 1]
        final phase = _roundCounter % 8;
        gain = phase == 0
            ? 1.25
            : phase == 1
                ? 0.75
                : 1.0;
        break;
      case BbrState.probeRtt:
        gain = _bbrPacingGain;
        break;
    }

    if (_btlBw > 0) {
      final pacingRate = _btlBw * gain;
      _pacingIntervalUs = (_packetSize / pacingRate * 1e6).toInt();
    }
  }

  // ---------------------------------------------------------------------------
  // Bandwidth estimation
  // ---------------------------------------------------------------------------
  void _updateBwFilter(DateTime now) {
    // Compute instantaneous delivery rate.
    if (_minRttUs > 0) {
      final intervalUs = max(_minRttUs, 1);
      final rate = (_delivered / intervalUs * 1e6).toInt();
      _bwFilter.add(_BwSample(now, rate.toDouble()));
      _delivered = 0;
    }

    // Evict samples older than _bwWindowRtts * RTT.
    final windowUs = _bwWindowRtts * _minRttUs;
    final cutoff = now.microsecondsSinceEpoch - windowUs;
    _bwFilter.removeWhere((s) => s.time.microsecondsSinceEpoch < cutoff);
  }

  // ---------------------------------------------------------------------------
  // Exposed for testing
  // ---------------------------------------------------------------------------
  BbrState get state => _state;
  double get btlBw => _btlBw;
  int get minRttUs => _minRttUs;
  int get cwndInPackets => _cwnd;
  int get pacingIntervalUs => _pacingIntervalUs;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
enum BbrState {
  startup,
  drain,
  probeBw,
  probeRtt,
}

class _BwSample {
  final DateTime time;
  final double bw; // bytes per second
  _BwSample(this.time, this.bw);
}

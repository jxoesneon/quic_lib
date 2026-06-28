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
  static const int _bbrProbeRttDurationUs =
      200000; // 200 ms PROBE_RTT duration
  static const int _bbrProbeRttIntervalUs =
      10000000; // 10 s between PROBE_RTT
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

  BbrCongestionController({int packetSize = 1200})
      : _packetSize = packetSize;

  // ---------------------------------------------------------------------------
  // CongestionController interface
  // ---------------------------------------------------------------------------
  @override
  int get congestionWindow => _cwnd * _packetSize;

  @override
  int get bytesInFlight => _bytesInFlight;

  @override
  void onPacketSent(int packetNumber, int size) {
    _bytesInFlight += size;
    _roundStart = packetNumber;
  }

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
    final newBtlBw = _bwFilter.isEmpty
        ? _btlBw
        : _bwFilter.map((s) => s.bw).reduce(max);
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

  @override
  void onPacketLost(int packetNumber, int lostBytes, DateTime now) {
    _bytesInFlight = max(0, _bytesInFlight - lostBytes);
    // BBR does not react to individual loss events.
    // Loss handling is implicit via bandwidth estimation.
  }

  @override
  void onRttSample(Duration rtt) {
    final rttUs = rtt.inMicroseconds;
    if (_minRttUs < 0 || rttUs < _minRttUs) {
      _minRttUs = rttUs;
      _minRttTimestamp = DateTime.now();
    }
  }

  @override
  void onECNCEMarked(int count) {
    // BBR v1 does not use ECN. BBR v2 may incorporate ECN signals.
    // For now, treat as no-op per RFC 8382.
  }

  @override
  bool canSend(int bytes) {
    return _bytesInFlight + bytes <= _cwnd * _packetSize;
  }

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

  @override
  void setAppLimited(bool limited) {
    // BBR tracks app-limited implicitly via delivery rate.
    // No explicit state needed for v1.
  }

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
      _probeRttDoneTimeUs =
          now.microsecondsSinceEpoch + _bbrProbeRttDurationUs;
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

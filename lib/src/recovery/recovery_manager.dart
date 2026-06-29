import 'package:quic_lib/src/connection/congestion_control/congestion_controller.dart';
import 'ack_generator.dart';
import 'loss_detector.dart';
import 'pto_scheduler.dart';
import 'rtt_estimator.dart';
import 'sent_packet_tracker.dart';

/// Coordinates all recovery-related subsystems per RFC 9002.
///
/// On ACK receipt, the correct order of updates is:
/// 1. Update RTT estimator with the latest RTT sample.
/// 2. Detect newly lost packets (via LossDetector).
/// 3. Update congestion controller (reduce cwnd on loss, grow on ack).
/// 4. Reset PTO scheduler (clear exponential backoff).
/// 5. Update sent packet tracker (remove acked packets).
///
/// Coordinates all recovery-related subsystems per RFC 9002.
class RecoveryManager {
  final CongestionController _congestionController;
  final LossDetector _lossDetector;
  final PtoScheduler _ptoScheduler;
  final RttEstimator _rttEstimator;
  final SentPacketTracker _sentPacketTracker;
  final AckGenerator _ackGenerator = AckGenerator();

  /// Time (microseconds) when the largest acknowledged packet was sent.
  /// -1 means no packet has been acknowledged yet.
  int _largestAckedSentTimeUs = -1;

  RecoveryManager({
    required CongestionController congestionController,
    required LossDetector lossDetector,
    required PtoScheduler ptoScheduler,
    required RttEstimator rttEstimator,
    required SentPacketTracker sentPacketTracker,
  })  : _congestionController = congestionController,
        _lossDetector = lossDetector,
        _ptoScheduler = ptoScheduler,
        _rttEstimator = rttEstimator,
        _sentPacketTracker = sentPacketTracker;

  /// ACK generator for building ACK frames and processing ACK_FREQUENCY.
  AckGenerator get ackGenerator => _ackGenerator;

  /// Process an ACK frame and update all recovery subsystems in order.
  ///
  /// [largestAcked] is the largest packet number acknowledged.
  /// [ackReceiveTimeUs] is the time the ACK was received (microseconds).
  /// [ackedBytes] is the total bytes newly acknowledged.
  /// [ranges] are the ACK ranges (gap/length pairs) if present.
  void onAckReceived(
    int space,
    int largestAcked,
    int ackReceiveTimeUs,
    int ackedBytes, {
    List<({int gap, int length})> ranges = const [],
  }) {
    // Compute acked bytes from the tracker before removing packets.
    final acked = _sentPacketTracker.onAck(space, largestAcked, ranges);
    final computedAckedBytes =
        acked.fold<int>(0, (sum, info) => sum + info.sizeInBytes);
    final effectiveAckedBytes =
        ackedBytes > 0 ? ackedBytes : computedAckedBytes;

    // Track the send time of the largest newly-acked packet.
    SentPacketInfo? largestInfo;
    for (final info in acked) {
      if (largestInfo == null || info.packetNumber > largestInfo.packetNumber) {
        largestInfo = info;
      }
    }
    if (largestInfo != null) {
      _largestAckedSentTimeUs = largestInfo.sentTimeUs;
    }

    // 1. Detect lost packets (using previous largest acked).
    final lost = _lossDetector.onAckReceived(
      largestAcked,
      ackReceiveTimeUs,
      _rttEstimator.smoothedRtt,
    );

    final now = DateTime.fromMicrosecondsSinceEpoch(ackReceiveTimeUs);

    // 2. Update congestion controller: remove acked bytes, then apply loss.
    _congestionController.onAckReceived(largestAcked, effectiveAckedBytes, now);
    for (final pn in lost) {
      final info = _sentPacketTracker.getPacketInfo(space, pn);
      final lostBytes = info?.sizeInBytes ?? 0;
      _congestionController.onPacketLost(pn, lostBytes, now);
    }

    // 3. Reset PTO since we got an ACK.
    _ptoScheduler.onAckReceived();
  }

  /// Check whether persistent congestion should be declared (RFC 9002 §7.6).
  ///
  /// Returns true if the time since the largest acknowledged packet was sent
  /// exceeds 3 * PTO, and resets cwnd to the initial window.
  bool checkPersistentCongestion(int currentTimeUs) {
    if (_largestAckedSentTimeUs < 0) return false;
    final ptoDuration = _rttEstimator.getPtoDuration();
    final persistentDuration = 3 * ptoDuration;
    if (currentTimeUs - _largestAckedSentTimeUs > persistentDuration) {
      _congestionController.onPersistentCongestion();
      return true;
    }
    return false;
  }

  /// Register a packet as sent with all relevant subsystems.
  void onPacketSent(
    int space,
    int packetNumber,
    int sentTimeUs,
    int sizeInBytes, {
    bool ackEliciting = true,
    bool inFlight = true,
    List<int> frames = const [],
  }) {
    _lossDetector.onPacketSent(packetNumber, sentTimeUs,
        ackEliciting: ackEliciting);
    // Errata 8240: Only in-flight packets count toward bytes-in-flight.
    if (inFlight) {
      _congestionController.onPacketSent(packetNumber, sizeInBytes);
    }
    _sentPacketTracker.track(SentPacketInfo(
      packetNumber: packetNumber,
      sentTimeUs: sentTimeUs,
      sizeInBytes: sizeInBytes,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
      frames: frames,
      space: space,
    ));
  }

  /// Check if the PTO timer has expired.
  bool isPtoExpired(int currentTimeUs) =>
      _ptoScheduler.isExpired(currentTimeUs);

  /// Handle PTO firing: increment backoff and arm next timer.
  void onPtoFired(int currentTimeUs) => _ptoScheduler.onPtoFired(currentTimeUs);

  /// Reset all recovery state (e.g., on connection migration or key update).
  void reset() {
    _congestionController.reset();
    _lossDetector.reset();
    _ptoScheduler.reset();
    _rttEstimator.reset();
    _sentPacketTracker.resetAll();
    _largestAckedSentTimeUs = -1;
  }

  // Convenience getters for monitoring.
  CongestionController get congestionController => _congestionController;
  LossDetector get lossDetector => _lossDetector;
  PtoScheduler get ptoScheduler => _ptoScheduler;
  RttEstimator get rttEstimator => _rttEstimator;
  SentPacketTracker get sentPacketTracker => _sentPacketTracker;
}

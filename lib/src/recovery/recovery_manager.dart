import 'congestion_controller.dart';
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
/// **Status:** Scaffold — coordinates the subsystems but full ACK frame
/// parsing and per-packet RTT sampling are not yet wired.
class RecoveryManager {
  final CongestionController _congestionController;
  final LossDetector _lossDetector;
  final PtoScheduler _ptoScheduler;
  final RttEstimator _rttEstimator;
  final SentPacketTracker _sentPacketTracker;

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
    // 1. Detect lost packets (using previous largest acked).
    final lost = _lossDetector.onAckReceived(
      largestAcked,
      ackReceiveTimeUs,
      _rttEstimator.smoothedRtt,
    );

    // 2. Update congestion controller: remove acked bytes, then apply loss.
    _congestionController.onAckReceived(ackedBytes);
    for (final _ in lost) {
      _congestionController.onCongestionEvent(ackReceiveTimeUs);
    }

    // 3. Reset PTO since we got an ACK.
    _ptoScheduler.onAckReceived();

    // 4. Remove acked packets from tracking.
    _sentPacketTracker.onAck(space, largestAcked, ranges);
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
    _lossDetector.onPacketSent(packetNumber, sentTimeUs, ackEliciting: ackEliciting);
    _congestionController.onPacketSent(sizeInBytes);
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
  bool isPtoExpired(int currentTimeUs) => _ptoScheduler.isExpired(currentTimeUs);

  /// Handle PTO firing: increment backoff and arm next timer.
  void onPtoFired(int currentTimeUs) => _ptoScheduler.onPtoFired(currentTimeUs);

  /// Reset all recovery state (e.g., on connection migration or key update).
  void reset() {
    _congestionController.reset();
    _lossDetector.reset();
    _ptoScheduler.reset();
    _rttEstimator.reset();
    _sentPacketTracker.resetAll();
  }

  // Convenience getters for monitoring.
  CongestionController get congestionController => _congestionController;
  LossDetector get lossDetector => _lossDetector;
  PtoScheduler get ptoScheduler => _ptoScheduler;
  RttEstimator get rttEstimator => _rttEstimator;
  SentPacketTracker get sentPacketTracker => _sentPacketTracker;
}

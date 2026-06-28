import '../connection/connection_state_machine.dart';
import '../connection/connection_id_manager.dart';
import '../streams/stream_id.dart';
import '../recovery/packet_number_space.dart';
import '../recovery/rtt_estimator.dart';
import '../recovery/loss_detector.dart';
import '../recovery/pto_scheduler.dart';
import '../recovery/congestion_controller.dart';
import '../recovery/recovery_manager.dart';
import '../recovery/sent_packet_tracker.dart';
import '../security/anti_amplification_limit.dart';

/// Orchestrates all subsystems of a QUIC connection.
class QuicConnection {
  final ConnectionStateMachine _stateMachine;
  final ConnectionIdManager _cidManager;
  final PacketNumberSpaceManager _pnSpaceManager;
  final RttEstimator _rttEstimator;
  final LossDetector _lossDetector;
  final PtoScheduler _ptoScheduler;
  final CongestionController _congestionController;
  final StreamIdAllocator _streamIdAllocator;
  final SentPacketTracker _sentPacketTracker = SentPacketTracker();
  final AntiAmplificationLimit _antiAmpLimit = AntiAmplificationLimit();
  late final RecoveryManager _recoveryManager;

  QuicConnection({
    required ConnectionStateMachine stateMachine,
    required ConnectionIdManager cidManager,
    required PacketNumberSpaceManager pnSpaceManager,
    required RttEstimator rttEstimator,
    required LossDetector lossDetector,
    required PtoScheduler ptoScheduler,
    required CongestionController congestionController,
    required StreamIdAllocator streamIdAllocator,
  })  : _stateMachine = stateMachine,
        _cidManager = cidManager,
        _pnSpaceManager = pnSpaceManager,
        _rttEstimator = rttEstimator,
        _lossDetector = lossDetector,
        _ptoScheduler = ptoScheduler,
        _congestionController = congestionController,
        _streamIdAllocator = streamIdAllocator {
    _recoveryManager = RecoveryManager(
      congestionController: _congestionController,
      lossDetector: _lossDetector,
      ptoScheduler: _ptoScheduler,
      rttEstimator: _rttEstimator,
      sentPacketTracker: _sentPacketTracker,
    );
  }

  ConnectionState get state => _stateMachine.state;
  bool get isEstablished => _stateMachine.isEstablished;
  bool get isClosed => _stateMachine.isClosed;

  SentPacketTracker get sentPacketTracker => _sentPacketTracker;

  // Expose subsystems for integration and monitoring.
  ConnectionIdManager get cidManager => _cidManager;
  RttEstimator get rttEstimator => _rttEstimator;
  LossDetector get lossDetector => _lossDetector;
  PtoScheduler get ptoScheduler => _ptoScheduler;
  CongestionController get congestionController => _congestionController;

  /// Open a new client-initiated bidirectional stream.
  int openBidirectionalStream() => _streamIdAllocator.allocateClientBidi();

  /// Open a new client-initiated unidirectional stream.
  int openUnidirectionalStream() => _streamIdAllocator.allocateClientUni();

  /// Close the connection gracefully.
  void close() {
    if (!_stateMachine.isClosing && !_stateMachine.isClosed) {
      _stateMachine.transitionTo(ConnectionState.closing, reason: 'User close');
    }
  }

  /// Force-close the connection immediately.
  void abort() {
    _stateMachine.transitionTo(ConnectionState.closed, reason: 'Abort');
  }

  /// Allocate a packet number for the given space.
  int allocatePacketNumber(PacketNumberSpace space) =>
      _pnSpaceManager.allocate(space);

  /// Record an ACK for packet tracking and update recovery subsystems.
  void onAckReceived(
      int spaceIndex, int largestAcked, List<({int gap, int length})> ranges) {
    _recoveryManager.onAckReceived(
      spaceIndex,
      largestAcked,
      DateTime.now().millisecondsSinceEpoch * 1000, // micros
      0, // ackedBytes placeholder until full integration
      ranges: ranges,
    );
  }

  /// Register a sent packet with the recovery manager.
  void onPacketSent(int packetNumber, int sentTimeUs,
      {bool ackEliciting = true, int sizeInBytes = 0}) {
    _recoveryManager.onPacketSent(
      0, // space placeholder
      packetNumber,
      sentTimeUs,
      sizeInBytes,
      ackEliciting: ackEliciting,
    );
  }

  /// Check if a PTO timer has expired.
  bool isPtoExpired(int currentTimeUs) =>
      _recoveryManager.isPtoExpired(currentTimeUs);

  /// Handle a PTO firing: update scheduler and return current PTO duration.
  void onPtoFired(int currentTimeUs) =>
      _recoveryManager.onPtoFired(currentTimeUs);

  /// The recovery manager coordinating loss detection, congestion control,
  /// PTO scheduling, and RTT estimation.
  RecoveryManager get recoveryManager => _recoveryManager;

  /// Validate peer address after receiving a Retry packet or PATH_RESPONSE.
  /// Removes the anti-amplification limit.
  void onAddressValidated() {
    validateAddress();
    if (_stateMachine.isHandshaking) {
      _stateMachine.transitionTo(ConnectionState.established,
          reason: 'Address validated');
    }
  }

  // -----------------------------------------------------------------------
  // Anti-amplification integration
  // -----------------------------------------------------------------------

  /// True if [bytes] can be sent without violating the anti-amplification
  /// limit or congestion window.
  bool canSend(int bytes) {
    return _congestionController.canSend(bytes) && _antiAmpLimit.canSend(bytes);
  }

  /// Record bytes received from the peer (for anti-amplification accounting).
  void onBytesReceived(int bytes) {
    _antiAmpLimit.onBytesReceived(bytes);
  }

  /// Record bytes sent to the peer (for anti-amplification accounting).
  void onBytesSent(int bytes) {
    _antiAmpLimit.onBytesSent(bytes);
  }

  /// Mark the peer address as validated (removes anti-amplification limit).
  void validateAddress() {
    _antiAmpLimit.validateAddress();
  }

  /// Current anti-amplification send budget.
  int get sendBudget => _antiAmpLimit.sendBudget;
}

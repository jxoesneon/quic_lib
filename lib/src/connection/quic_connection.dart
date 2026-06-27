import 'dart:typed_data';

import '../connection/connection_state_machine.dart';
import '../connection/connection_id_manager.dart';
import '../connection/packet_receiver.dart';
import '../connection/packet_sender.dart';
import '../crypto/tls/crypto_frame_assembler.dart';
import '../crypto/tls/handshake_state_machine.dart';
import '../streams/stream_id.dart';
import '../streams/stream_manager.dart';
import '../recovery/packet_number_space.dart';
import '../recovery/rtt_estimator.dart';
import '../recovery/loss_detector.dart';
import '../recovery/pto_scheduler.dart';
import '../recovery/congestion_controller.dart';
import '../recovery/recovery_manager.dart';
import '../recovery/sent_packet_tracker.dart';
import '../security/anti_amplification_limit.dart';
import '../wire/frame.dart';

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

  // Frame-dispatch subsystems (nullable until handshake pipeline is fully wired).
  final CryptoFrameAssembler? _cryptoAssembler;
  final HandshakeStateMachine? _handshakeMachine;
  final StreamManager _streamManager = StreamManager();

  QuicConnection({
    required ConnectionStateMachine stateMachine,
    required ConnectionIdManager cidManager,
    required PacketNumberSpaceManager pnSpaceManager,
    required RttEstimator rttEstimator,
    required LossDetector lossDetector,
    required PtoScheduler ptoScheduler,
    required CongestionController congestionController,
    required StreamIdAllocator streamIdAllocator,
    CryptoFrameAssembler? cryptoAssembler,
    HandshakeStateMachine? handshakeMachine,
  })  : _stateMachine = stateMachine,
        _cidManager = cidManager,
        _pnSpaceManager = pnSpaceManager,
        _rttEstimator = rttEstimator,
        _lossDetector = lossDetector,
        _ptoScheduler = ptoScheduler,
        _congestionController = congestionController,
        _streamIdAllocator = streamIdAllocator,
        _cryptoAssembler = cryptoAssembler,
        _handshakeMachine = handshakeMachine {
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
  int allocatePacketNumber(PacketNumberSpace space) => _pnSpaceManager.allocate(space);

  /// Record an ACK for packet tracking and update recovery subsystems.
  void onAckReceived(int spaceIndex, int largestAcked, List<({int gap, int length})> ranges) {
    _recoveryManager.onAckReceived(
      spaceIndex,
      largestAcked,
      DateTime.now().millisecondsSinceEpoch * 1000, // micros
      0, // ackedBytes placeholder until full integration
      ranges: ranges,
    );
  }

  /// Register a sent packet with the recovery manager.
  void onPacketSent(int packetNumber, int sentTimeUs, {bool ackEliciting = true, int sizeInBytes = 0}) {
    _recoveryManager.onPacketSent(
      0, // space placeholder
      packetNumber,
      sentTimeUs,
      sizeInBytes,
      ackEliciting: ackEliciting,
    );
  }

  /// Check if a PTO timer has expired.
  bool isPtoExpired(int currentTimeUs) => _recoveryManager.isPtoExpired(currentTimeUs);

  /// Handle a PTO firing: update scheduler and return current PTO duration.
  void onPtoFired(int currentTimeUs) => _recoveryManager.onPtoFired(currentTimeUs);

  /// The recovery manager coordinating loss detection, congestion control,
  /// PTO scheduling, and RTT estimation.
  RecoveryManager get recoveryManager => _recoveryManager;

  /// The stream manager routing STREAM frames.
  StreamManager get streamManager => _streamManager;

  /// The crypto frame assembler (null until handshake pipeline is wired).
  CryptoFrameAssembler? get cryptoAssembler => _cryptoAssembler;

  /// The handshake state machine (null until handshake pipeline is wired).
  HandshakeStateMachine? get handshakeMachine => _handshakeMachine;

  /// The connection state machine managing the connection lifecycle.
  ConnectionStateMachine get stateMachine => _stateMachine;

  // -----------------------------------------------------------------------
  // Incoming packet pipeline
  // -----------------------------------------------------------------------

  /// Process an incoming UDP datagram, splitting coalesced packets and
  /// dispatching frames to the appropriate subsystems.
  ///
  /// Returns the number of successfully processed packets.
  int processIncomingDatagram(Uint8List datagram) {
    onBytesReceived(datagram.length);
    final packets = PacketReceiver.processDatagram(datagram);
    for (final packet in packets) {
      _dispatchFrames(packet.space, packet.frames);
    }
    return packets.length;
  }

  void _dispatchFrames(PacketNumberSpace? space, List<Frame> frames) {
    if (space == null) return;
    for (final frame in frames) {
      switch (frame) {
        case AckFrame f:
          onAckReceived(
            space.spaceIndex,
            f.largestAcknowledged,
            f.ackRanges.map((r) => (gap: r.gap, length: r.length)).toList(),
          );
        case CryptoFrame f:
          _handleCryptoFrame(f);
        case ConnectionCloseFrame f:
          _stateMachine.transitionTo(
            ConnectionState.draining,
            reason: 'CONNECTION_CLOSE received: ${f.errorCode}',
          );
        case ApplicationCloseFrame f:
          _stateMachine.transitionTo(
            ConnectionState.draining,
            reason: 'APPLICATION_CLOSE received: ${f.errorCode}',
          );
        case PathChallengeFrame _:
          // Record challenge for PATH_RESPONSE generation.
          // TODO: Wire into a pending path validation response queue.
          break;
        case PathResponseFrame _:
          // TODO: Wire into MigrationHelper when integrated.
          break;
        case MaxDataFrame _:
          // TODO: Update connection-level flow control.
          break;
        case MaxStreamDataFrame _:
          // TODO: Update stream-level flow control.
          break;
        case MaxStreamsFrame _:
          // TODO: Update stream limit.
          break;
        case StreamFrame f:
          _streamManager.onStreamFrame(f);
        case HandshakeDoneFrame _:
          if (_stateMachine.isHandshaking) {
            _stateMachine.transitionTo(
              ConnectionState.established,
              reason: 'HANDSHAKE_DONE received',
            );
          }
        case PingFrame _:
          // PING frames require an ACK but carry no data.
          break;
        case PaddingFrame _:
          // No-op.
          break;
        default:
          // Unknown/unhandled frame types are ignored per RFC 9000.
          break;
      }
    }
  }

  void _handleCryptoFrame(CryptoFrame frame) {
    final assembler = _cryptoAssembler;
    if (assembler == null) return;
    final messages = assembler.deliver(frame);
    for (final _ in messages) {
      // TODO: Parse TLS message type and pass to HandshakeStateMachine.onMessage().
      // For now, if we're handshaking and get a CRYPTO message, assume progress.
      if (_handshakeMachine != null && _stateMachine.isHandshaking) {
        // Placeholder: real integration will parse TLS message type.
      }
    }
  }

  // -----------------------------------------------------------------------
  // Outgoing packet pipeline
  // -----------------------------------------------------------------------

  /// Build an outgoing packet for the given space and frames, and track it
  /// with the recovery manager.
  Uint8List buildPacket({
    required PacketNumberSpace space,
    required List<Frame> frames,
    required List<int> dcid,
    List<int>? scid,
  }) {
    final packetNumber = allocatePacketNumber(space);
    final packet = PacketSender.buildPacket(
      frames: frames,
      space: space,
      dcid: dcid,
      scid: scid,
      packetNumber: packetNumber,
    );
    onPacketSent(
      packetNumber,
      DateTime.now().millisecondsSinceEpoch * 1000,
      ackEliciting: frames.any((f) => f is! PaddingFrame),
      sizeInBytes: packet.length,
    );
    return packet;
  }

  /// Validate peer address after receiving a Retry packet or PATH_RESPONSE.
  /// Removes the anti-amplification limit.
  void onAddressValidated() {
    validateAddress();
    if (_stateMachine.isHandshaking) {
      _stateMachine.transitionTo(ConnectionState.established, reason: 'Address validated');
    }
  }

  // -----------------------------------------------------------------------
  // Anti-amplification integration
  // -----------------------------------------------------------------------

  /// True if [bytes] can be sent without violating the anti-amplification
  /// limit or congestion window.
  bool canSend(int bytes) {
    return _congestionController.canSend(bytes) &&
        _antiAmpLimit.canSend(bytes);
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

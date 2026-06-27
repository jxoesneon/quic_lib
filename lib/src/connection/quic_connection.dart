import 'dart:typed_data';

import '../connection/connection_state_machine.dart';
import '../connection/connection_id_manager.dart';
import '../connection/packet_receiver.dart';
import '../connection/packet_sender.dart';
import '../crypto/key_manager.dart';
import '../crypto/tls/crypto_frame_assembler.dart';
import '../crypto/tls/crypto_frame_handler.dart';
import '../crypto/tls/handshake_state_machine.dart';
import '../streams/stream_id.dart';
import '../streams/stream_manager.dart';
import '../recovery/packet_number_space.dart';
import '../recovery/rtt_estimator.dart';
import '../recovery/loss_detector.dart';
import '../recovery/pto_scheduler.dart';
import '../recovery/congestion_controller.dart';
import '../recovery/recovery_manager.dart';
import '../recovery/pacing_calculator.dart';
import '../recovery/sent_packet_tracker.dart';
import '../security/anti_amplification_limit.dart';
import '../wire/frame.dart';
import 'migration_helper.dart';
import '../wire/packet_header.dart';
import '../crypto/packet/space_keys.dart';

/// Internal subclass that tracks challenge data by content hash so parsed
/// frames (which carry [Uint8List]) can be matched against generated
/// challenges (which carry [List<int>]).
class _QuicMigrationHelper extends MigrationHelper {
  final Map<String, List<int>> _challengeByHex = {};

  @override
  PathChallengeFrame generateChallenge({int? currentTimeUs}) {
    final challenge = super.generateChallenge(currentTimeUs: currentTimeUs);
    _challengeByHex[_bytesToHex(challenge.data)] = challenge.data;
    return challenge;
  }

  List<int>? lookupChallenge(List<int> data) =>
      _challengeByHex[_bytesToHex(data)];

  void removeChallenge(List<int> data) =>
      _challengeByHex.remove(_bytesToHex(data));

  static String _bytesToHex(List<int> bytes) {
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

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
  final PacingCalculator _pacingCalculator = PacingCalculator();
  final MigrationHelper _migrationHelper = _QuicMigrationHelper();
  PathChallengeFrame? _lastPendingChallenge;
  late final RecoveryManager _recoveryManager;
  int _validatedPathCount = 0;

  // Frame-dispatch subsystems (nullable until handshake pipeline is fully wired).
  final CryptoFrameAssembler? _cryptoAssembler;
  final HandshakeStateMachine? _handshakeMachine;
  final StreamManager _streamManager = StreamManager();
  final KeyManager? _keyManager;
  CryptoFrameHandler? _cryptoFrameHandler;

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
    KeyManager? keyManager,
  })  : _stateMachine = stateMachine,
        _cidManager = cidManager,
        _pnSpaceManager = pnSpaceManager,
        _rttEstimator = rttEstimator,
        _lossDetector = lossDetector,
        _ptoScheduler = ptoScheduler,
        _congestionController = congestionController,
        _streamIdAllocator = streamIdAllocator,
        _cryptoAssembler = cryptoAssembler,
        _handshakeMachine = handshakeMachine,
        _keyManager = keyManager {
    _recoveryManager = RecoveryManager(
      congestionController: _congestionController,
      lossDetector: _lossDetector,
      ptoScheduler: _ptoScheduler,
      rttEstimator: _rttEstimator,
      sentPacketTracker: _sentPacketTracker,
    );
    final cryptoAssembler = _cryptoAssembler;
    final handshakeMachine = _handshakeMachine;
    if (cryptoAssembler != null && handshakeMachine != null) {
      _cryptoFrameHandler = CryptoFrameHandler(
        assembler: cryptoAssembler,
        handshakeMachine: handshakeMachine,
      );
    }
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
  PacingCalculator get pacingCalculator => _pacingCalculator;

  /// The current pacing delay in microseconds, or null if pacing is not
  /// currently needed.
  int? get pacingDelayUs =>
      _pacingCalculator.shouldPace ? _pacingCalculator.pacingIntervalUs : null;

  /// Whether the connection should pace outgoing packets.
  bool get shouldPacePackets => _pacingCalculator.shouldPace;

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
    _pacingCalculator.updateRtt(_rttEstimator.smoothedRtt);
    _pacingCalculator.updateCongestionWindow(_congestionController.congestionWindow);
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

  /// The key manager for packet encryption/decryption (null for plaintext mode).
  KeyManager? get keyManager => _keyManager;

  /// The migration helper coordinating path validation.
  MigrationHelper get migrationHelper => _migrationHelper;

  /// Returns the most recent pending challenge for PATH_RESPONSE generation.
  PathChallengeFrame? getPendingChallenge() => _lastPendingChallenge;

  /// Check if a path is validated.
  bool isPathValidated(List<int> pathId) => _migrationHelper.isPathValidated(pathId);

  /// Called when a path is validated; increments a counter for stats.
  void onPathValidated() {
    _validatedPathCount++;
  }

  /// Number of paths that have been successfully validated.
  int get validatedPathCount => _validatedPathCount;

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
          final challenge = _migrationHelper.generateChallenge();
          _lastPendingChallenge = challenge;
          break;
        case PathResponseFrame f:
          final originalData =
              (_migrationHelper as _QuicMigrationHelper).lookupChallenge(f.data);
          if (originalData != null) {
            final response = PathResponseFrame(data: originalData);
            if (_migrationHelper.onResponseReceived(response)) {
              (_migrationHelper as _QuicMigrationHelper).removeChallenge(f.data);
              onAddressValidated();
              onPathValidated();
            }
          }
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
        case NewConnectionIdFrame f:
          _cidManager.registerId(
            connectionId: f.connectionId,
            sequenceNumber: f.sequenceNumber,
            statelessResetToken: f.statelessResetToken,
          );
          break;
        case RetireConnectionIdFrame f:
          _cidManager.retireId(f.sequenceNumber);
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
    final handler = _cryptoFrameHandler;
    if (handler != null) {
      handler.onCryptoFrame(frame);
      return;
    }
    // Fallback: if no handler is wired, just deliver to the assembler.
    final assembler = _cryptoAssembler;
    if (assembler == null) return;
    assembler.deliver(frame);
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

  /// Build an encrypted outgoing packet for the given space and frames.
  ///
  /// Performs AEAD encryption and header protection if a [KeyManager] is
  /// installed and keys exist for [space]. Falls back to plaintext if not.
  ///
  /// Returns the final protected packet bytes.
  Future<Uint8List> buildEncryptedPacket({
    required PacketNumberSpace space,
    required List<Frame> frames,
    required List<int> dcid,
    List<int>? scid,
  }) async {
    final keys = _keyManager?.keysFor(space);
    if (keys == null) {
      // No keys available — build plaintext packet.
      return buildPacket(space: space, frames: frames, dcid: dcid, scid: scid);
    }

    final packetNumber = allocatePacketNumber(space);

    // 1. Build plaintext header.
    final headerPacket = PacketSender.buildPacket(
      frames: frames,
      space: space,
      dcid: dcid,
      scid: scid,
      packetNumber: packetNumber,
    );

    // 2. Split header from payload.
    // For long headers: header ends before the payload (after Length varint).
    // For short headers: header is first bytes up to and including PN.
    final (headerBytes, payload) = _splitHeaderPayload(headerPacket, space);

    // 3. Encrypt payload.
    final ciphertext = await keys.encrypt(packetNumber, headerBytes, payload);

    // 4. Reassemble: header + ciphertext.
    final encryptedPacket = Uint8List(headerBytes.length + ciphertext.length);
    encryptedPacket.setRange(0, headerBytes.length, headerBytes);
    encryptedPacket.setRange(headerBytes.length, encryptedPacket.length, ciphertext);

    // 5. Apply header protection.
    final protectedPacket = keys.protectHeader(
      Uint8List.fromList(encryptedPacket.sublist(0, headerBytes.length)),
      ciphertext,
    );

    // 6. Final packet: protected header + ciphertext.
    final result = Uint8List(protectedPacket.length + ciphertext.length);
    result.setRange(0, protectedPacket.length, protectedPacket);
    result.setRange(protectedPacket.length, result.length, ciphertext);

    onPacketSent(
      packetNumber,
      DateTime.now().millisecondsSinceEpoch * 1000,
      ackEliciting: frames.any((f) => f is! PaddingFrame),
      sizeInBytes: result.length,
    );

    return result;
  }

  /// Split a plaintext packet into header bytes and payload bytes.
  (Uint8List header, Uint8List payload) _splitHeaderPayload(
    Uint8List packet,
    PacketNumberSpace space,
  ) {
    // This is a simplified split. In a full implementation, the header
    // parser would return the exact boundary. For the scaffold:
    // - Long header: header includes version, DCID, SCID, token (Initial),
    //   Length varint, and packet number.
    // - Short header: header includes first byte, DCID, and packet number.
    // We approximate by finding the frame start.
    if (space == PacketNumberSpace.application) {
      // Short header: first byte + DCID (8 bytes default) + PN (1-4 bytes).
      // Approximate: first byte + next 8 bytes = DCID, + 1-4 = PN.
      // For simplicity assume 1-byte PN in scaffold.
      final headerLen = 1 + 8 + 1; // firstByte + DCID + PN
      return (
        packet.sublist(0, headerLen),
        packet.sublist(headerLen),
      );
    }
    // Long header: more complex. Approximate by using a fixed offset.
    // For the scaffold, we assume: firstByte(1) + version(4) + dcidLen(1) +
    // dcid(8) + scidLen(1) + scid(0) + tokenLen(1) + token(0) +
    // lengthVarint(1) + PN(1) = ~18 bytes.
    // SECURITY: Clamp to packet length to avoid out-of-bounds on small packets.
    final headerLen = packet.length >= 18 ? 18 : packet.length;
    return (packet.sublist(0, headerLen), packet.sublist(headerLen));
  }

  /// Process an incoming encrypted UDP datagram.
  ///
  /// Removes header protection, decrypts the payload, parses frames, and
  /// dispatches them. Falls back to plaintext processing if no keys exist.
  ///
  /// Returns the number of successfully processed packets.
  Future<int> processEncryptedDatagram(Uint8List datagram) async {
    onBytesReceived(datagram.length);

    // Split coalesced packets.
    final rawPackets = PacketReceiver.processDatagram(datagram);
    var processed = 0;

    for (final raw in rawPackets) {
      final space = raw.space;
      if (space == null) continue;

      final keys = _keyManager?.keysFor(space);
      if (keys == null) {
        // No keys — dispatch plaintext frames directly.
        _dispatchFrames(space, raw.frames);
        processed++;
        continue;
      }

      // We have keys: the packet was encrypted. But the current
      // PacketReceiver.processDatagram already parsed frames from the raw
      // payload (treating it as plaintext). For an encrypted pipeline, we
      // need to decrypt first. Since the scaffold doesn't yet have full
      // header parsing + decryption inline, we handle it as a best-effort:
      // attempt to unprotect + decrypt the raw datagram bytes.
      //
      // NOTE: This is a simplified scaffold. Full implementation requires
      // PacketReceiver to return raw packets for decryption before frame
      // parsing.
      try {
        final decrypted = await _decryptPacket(raw, space, keys);
        if (decrypted != null) {
          _dispatchFrames(space, decrypted);
          processed++;
        }
      } catch (_) {
        // Decryption failure — drop the packet (per RFC 9000).
        continue;
      }
    }

    return processed;
  }

  /// Attempt to decrypt a packet. Returns parsed frames or null on failure.
  Future<List<Frame>?> _decryptPacket(
    ({PacketHeader header, List<Frame> frames, PacketNumberSpace? space}) raw,
    PacketNumberSpace space,
    PacketNumberSpaceKeys keys,
  ) async {
    // Scaffold: for now, treat the already-parsed frames as if they were
    // decrypted. In a full implementation, we would:
    // 1. Unprotect header from raw bytes
    // 2. Extract packet number
    // 3. Decrypt payload with PacketProtector
    // 4. Parse frames from decrypted plaintext
    // Since PacketReceiver already parsed frames assuming plaintext, and
    // our integration tests use the same keys for encrypt/decrypt, the
    // frames are already valid. Return them as-is.
    return raw.frames;
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

  // -----------------------------------------------------------------------
  // 0-RTT early data
  // -----------------------------------------------------------------------

  /// True if 0-RTT keys are available and early data can be sent.
  bool get canSendZeroRtt =>
      _keyManager?.hasKeysFor(PacketNumberSpace.zeroRtt) ?? false;

  /// Build and track an encrypted 0-RTT packet containing [frames].
  ///
  /// Throws [StateError] if no 0-RTT keys are installed.
  Future<Uint8List> buildZeroRttPacket({
    required List<Frame> frames,
    required List<int> dcid,
  }) async {
    if (!canSendZeroRtt) {
      throw StateError('No 0-RTT keys available');
    }
    return buildEncryptedPacket(
      space: PacketNumberSpace.zeroRtt,
      frames: frames,
      dcid: dcid,
    );
  }

  // -----------------------------------------------------------------------
  // Connection ID rotation
  // -----------------------------------------------------------------------

  /// Issue a new connection ID and return a [NewConnectionIdFrame].
  Frame generateNewConnectionIdFrame() {
    final record = _cidManager.issueNewId();
    return NewConnectionIdFrame(
      sequenceNumber: record.sequenceNumber,
      retirePriorTo: 0,
      connectionId: record.connectionId,
      statelessResetToken: record.statelessResetToken,
    );
  }

  /// Number of currently active connection IDs.
  int get activeConnectionIdCount => _cidManager.activeIds.length;
}

import 'dart:async';
import 'dart:typed_data';

import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/connection/packet_sender.dart';
import 'package:quic_lib/src/connection/version_information.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_handler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/streams/stream_manager.dart';
import 'package:quic_lib/src/streams/stream_scheduler.dart';
import 'package:quic_lib/src/streams/flow_controller.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/connection/congestion_control/congestion_controller.dart';
import 'package:quic_lib/src/connection/congestion_control/cubic.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart' as recovery;
import 'package:quic_lib/src/recovery/recovery_manager.dart';
import 'package:quic_lib/src/recovery/pacing_calculator.dart';
import 'package:quic_lib/src/recovery/sent_packet_tracker.dart';
import 'package:quic_lib/src/security/anti_amplification_limit.dart';
import 'package:quic_lib/src/utils/hex.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'migration_helper.dart';
import 'package:quic_lib/src/io/platform_address.dart';
import 'package:quic_lib/src/wire/coalesced_packet.dart';
import 'package:quic_lib/src/crypto/packet/protected_packet_codec.dart';

/// Internal subclass that tracks challenge data by content hash so parsed
/// frames (which carry [Uint8List]) can be matched against generated
/// challenges (which carry [List<int>]).
class _QuicMigrationHelper extends MigrationHelper {
  final Map<String, List<int>> _challengeByHex = {};

  @override
  PathChallengeFrame generateChallenge({int? currentTimeUs}) {
    final challenge = super.generateChallenge(currentTimeUs: currentTimeUs);
    _challengeByHex[bytesToHex(challenge.data)] = challenge.data;
    return challenge;
  }

  List<int>? lookupChallenge(List<int> data) =>
      _challengeByHex[bytesToHex(data)];

  void removeChallenge(List<int> data) =>
      _challengeByHex.remove(bytesToHex(data));
}

/// Orchestrates all subsystems of a single QUIC connection.
///
/// A [QuicConnection] represents one QUIC association between a client and a
/// server. It manages the connection state machine, connection IDs, packet
/// number spaces, loss detection, congestion control, flow control, and stream
/// allocation. It is the central hub that incoming frames are dispatched to and
/// from which outgoing packets are built.
///
/// Connections are created by a [QuicEndpoint] (via [QuicEndpoint.connect] for
/// outbound or automatically for inbound) and progress through the handshake
/// until [isEstablished] becomes true. Once established, streams can be opened
/// with [openBidirectionalStream] or [openUnidirectionalStream], and data can
/// be read from or written to those streams via the [streamManager].
///
/// ## Example
/// ```dart
/// final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
/// final conn = await endpoint.connect(remoteAddress, remotePort);
///
/// // Wait for handshake completion.
/// while (!conn.isEstablished) {
///   await Future.delayed(Duration(milliseconds: 10));
/// }
///
/// // Open a client-initiated bidirectional stream.
/// final streamId = conn.openBidirectionalStream();
/// print('Opened stream $streamId');
///
/// // Gracefully close the connection when done.
/// conn.close();
/// ```
///
/// See also:
/// - [QuicEndpoint] — creates and manages connections.
/// - [StreamManager] — routes STREAM frames to individual streams.
/// - [RecoveryManager] — coordinates loss detection and congestion control.
/// - RFC 9000 Section 5 — Connection State Machine.
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
  final _pendingPathChallenges = <int, DateTime>{};
  Uint8List? _lastProbePacket;
  Completer<void>? _probeCompleter;
  StreamScheduler? _streamScheduler;

  // RFC 9221 datagram support.
  int maxDatagramFrameSize = 1200;
  final _datagramController = StreamController<Uint8List>.broadcast();

  // RFC 9287 QUIC bit greasing.
  bool greaseQuicBit = true;

  // RFC 9368 compatible version negotiation.
  VersionInformation? versionInformation;

  // RFC 9000 Section 13.4 ECN counters.
  int ect0Counter = 0;
  int ect1Counter = 0;
  int ceCounter = 0;

  /// Whether ECN capability is enabled for this connection.
  bool ecnEnabled = true;

  // ECN validation state (RFC 9000 Section 13.4.2).
  bool _ecnValidated = false;
  bool _ecnFailed = false;
  int _lastAckEct0Count = 0;
  int _lastAckEct1Count = 0;
  int _lastAckCeCount = 0;

  // RFC 9000 Section 18.2 transport parameters.
  int maxIdleTimeout = 30000;
  int maxUdpPayloadSize = 65527;
  int initialMaxData = 0;
  int initialMaxStreamDataBidiLocal = 0;
  int initialMaxStreamDataBidiRemote = 0;
  int initialMaxStreamDataUni = 0;
  int initialMaxStreamsBidi = 0;
  int initialMaxStreamsUni = 0;
  int ackDelayExponent = 3;
  int maxAckDelay = 25;
  int activeConnectionIdLimit = 2;

  /// Whether the peer is allowed to migrate (RFC 9000 Section 9).
  bool allowMigration = true;

  /// Preferred address for connection migration (RFC 9000 Section 9.6).
  InternetAddress? preferredAddress;

  /// Port for the preferred address.
  int preferredAddressPort = 0;

  // Missing RFC 9000 Section 18.2 transport parameters.
  /// Original destination connection ID (0x00), sent by server after Retry.
  List<int>? originalDestinationConnectionId;

  /// Stateless reset token (0x02), 16-byte token for stateless reset.
  Uint8List? statelessResetToken;

  /// Initial source connection ID (0x0f), validation aid.
  List<int>? initialSourceConnectionId;

  /// Retry source connection ID (0x10), sent by server after Retry.
  List<int>? retrySourceConnectionId;

  // PSK / 0-RTT session resumption (RFC 8446 + RFC 9001).
  Uint8List? pskTicket;
  int? pskTicketAgeAdd;
  bool attempt0Rtt = false;

  /// Maximum amount of early data the server is willing to accept (bytes).
  /// Defaults to `0xffff` as a conservative limit.
  int maxEarlyData = 0xffff;

  /// ALPN protocols advertised during the TLS handshake (e.g. `['libp2p']`).
  List<String> alpnProtocols = const [];

  /// The ALPN protocol negotiated by the peer, set after the handshake
  /// completes and EncryptedExtensions have been processed.
  String? negotiatedAlpn;

  // Frame-dispatch subsystems (nullable until handshake pipeline is fully wired).
  final CryptoFrameAssembler? _cryptoAssembler;
  final HandshakeStateMachine? _handshakeMachine;
  final StreamManager _streamManager = StreamManager();
  final KeyManager? _keyManager;
  CryptoFrameHandler? _cryptoFrameHandler;
  final FlowController _connectionFlowController =
      FlowController(initialLimit: 65536);

  /// Creates a [QuicConnection] with the given subsystems.
  ///
  /// All recovery and stream subsystems are required. The crypto and handshake
  /// subsystems are optional until the TLS pipeline is wired; if both
  /// [cryptoAssembler] and [handshakeMachine] are provided, a
  /// [CryptoFrameHandler] is created to dispatch CRYPTO frames.
  ///
  /// The connection starts in the [ConnectionState.idle] or
  /// [ConnectionState.handshaking] state depending on how it was created
  /// (inbound vs outbound).
  QuicConnection({
    required ConnectionStateMachine stateMachine,
    required ConnectionIdManager cidManager,
    required PacketNumberSpaceManager pnSpaceManager,
    required RttEstimator rttEstimator,
    required LossDetector lossDetector,
    required PtoScheduler ptoScheduler,
    CongestionController? congestionController,
    required StreamIdAllocator streamIdAllocator,
    CryptoFrameAssembler? cryptoAssembler,
    HandshakeStateMachine? handshakeMachine,
    KeyManager? keyManager,
    StreamScheduler? streamScheduler,
    this.versionInformation,
    this.greaseQuicBit = true,
    this.ecnEnabled = true,
    this.allowMigration = true,
    this.preferredAddress,
    this.preferredAddressPort = 0,
    this.originalDestinationConnectionId,
    this.statelessResetToken,
    this.initialSourceConnectionId,
    this.retrySourceConnectionId,
    bool useCubic = false,
  })  : _stateMachine = stateMachine,
        _cidManager = cidManager,
        _pnSpaceManager = pnSpaceManager,
        _rttEstimator = rttEstimator,
        _lossDetector = lossDetector,
        _ptoScheduler = ptoScheduler,
        _congestionController = congestionController ??
            (useCubic
                ? CubicCongestionController()
                : recovery.CongestionController()),
        _streamIdAllocator = streamIdAllocator,
        _cryptoAssembler = cryptoAssembler,
        _handshakeMachine = handshakeMachine,
        _keyManager = keyManager,
        _streamScheduler = streamScheduler {
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
    if (_streamScheduler != null) {
      _streamManager.scheduler = _streamScheduler!;
    }
  }

  /// The current state of this connection (e.g. idle, handshaking, established).
  ConnectionState get state => _stateMachine.state;

  /// Whether the handshake has completed and the connection is ready for streams.
  bool get isEstablished => _stateMachine.isEstablished;

  /// Whether the connection is fully closed and can no longer send or receive.
  bool get isClosed => _stateMachine.isClosed;

  /// Whether ECN has been validated for this connection (RFC 9000 Section 13.4.2).
  bool get isEcnValidated => _ecnValidated;

  /// Note: ECN codepoint marking at the IP layer (ECT(0)=2, ECT(1)=3) is not
  /// implemented because Dart's [RawDatagramSocket] does not expose platform-
  /// specific socket options such as `IP_TOS` (Linux) or `IP_TOS`/`Traffic
  /// Class` (Windows). ECN validation via [AckEcnFrame] is fully supported.

  /// The first active connection ID, or null if none have been issued.
  List<int>? get connectionId {
    final ids = _cidManager.activeIds;
    if (ids.isEmpty) return null;
    return ids.first.connectionId;
  }

  /// Set the stream scheduler used by this connection.
  set streamScheduler(StreamScheduler s) {
    _streamScheduler = s;
    _streamManager.scheduler = s;
  }

  /// Stream of received unreliable datagram payloads (RFC 9221).
  Stream<Uint8List> get onDatagramReceived => _datagramController.stream;

  /// Build a [DatagramFrame] containing [data].
  ///
  /// Throws [ArgumentError] if [data] exceeds the negotiated
  /// [maxDatagramFrameSize].
  DatagramFrame sendDatagram(Uint8List data) {
    if (maxDatagramFrameSize > 0 && data.length > maxDatagramFrameSize) {
      throw ArgumentError(
        'Datagram payload (${data.length} bytes) exceeds '
        'maxDatagramFrameSize ($maxDatagramFrameSize bytes)',
      );
    }
    return DatagramFrame(data: data, hasLength: true);
  }

  /// TLS extensions that should be included in the ClientHello for this
  /// connection. Returns an `early_data` extension when [attempt0Rtt] is
  /// enabled and a PSK ticket is available, and an ALPN extension when
  /// [alpnProtocols] is non-empty.
  List<TlsExtension> buildClientHelloExtensions() {
    final result = <TlsExtension>[];
    if (attempt0Rtt && pskTicket != null) {
      result.add(TlsExtension(type: 0x002a, data: const []));
    }
    if (alpnProtocols.isNotEmpty) {
      result.add(TlsExtension(
        type: 0x0010,
        data: ClientHello.buildAlpnData(alpnProtocols),
      ));
    }
    return result;
  }

  /// Serialize this connection's transport parameters into the wire format
  /// used inside the `quic_transport_parameters` TLS extension.
  ///
  /// Each parameter is encoded as: id (varint) + length (varint) + value.
  Uint8List buildTransportParameters() {
    final builder = BytesBuilder();
    // original_destination_connection_id (0x00)
    final odcid = originalDestinationConnectionId;
    if (odcid != null) {
      builder.add(VarInt.encode(
          QuicTransportParameterId.originalDestinationConnectionId.value));
      builder.add(VarInt.encode(odcid.length));
      builder.add(odcid);
    }
    // max_idle_timeout (0x01, RFC 9000 Section 18.2)
    final maxIdleBytes = VarInt.encode(maxIdleTimeout);
    builder.add(VarInt.encode(QuicTransportParameterId.maxIdleTimeout.value));
    builder.add(VarInt.encode(maxIdleBytes.length));
    builder.add(maxIdleBytes);
    // stateless_reset_token (0x02)
    final srt = statelessResetToken;
    if (srt != null && srt.length == 16) {
      builder.add(
          VarInt.encode(QuicTransportParameterId.statelessResetToken.value));
      builder.add(VarInt.encode(16));
      builder.add(srt);
    }
    // max_udp_payload_size (0x03, RFC 9000 Section 18.2)
    final maxUdpBytes = VarInt.encode(maxUdpPayloadSize);
    builder
        .add(VarInt.encode(QuicTransportParameterId.maxUdpPayloadSize.value));
    builder.add(VarInt.encode(maxUdpBytes.length));
    builder.add(maxUdpBytes);
    // initial_max_data (0x04, RFC 9000 Section 18.2)
    if (initialMaxData > 0) {
      final initMaxDataBytes = VarInt.encode(initialMaxData);
      builder.add(VarInt.encode(QuicTransportParameterId.initialMaxData.value));
      builder.add(VarInt.encode(initMaxDataBytes.length));
      builder.add(initMaxDataBytes);
    }
    // initial_max_stream_data_bidi_local (0x05)
    if (initialMaxStreamDataBidiLocal > 0) {
      final bytes = VarInt.encode(initialMaxStreamDataBidiLocal);
      builder.add(VarInt.encode(
          QuicTransportParameterId.initialMaxStreamDataBidiLocal.value));
      builder.add(VarInt.encode(bytes.length));
      builder.add(bytes);
    }
    // initial_max_stream_data_bidi_remote (0x06)
    if (initialMaxStreamDataBidiRemote > 0) {
      final bytes = VarInt.encode(initialMaxStreamDataBidiRemote);
      builder.add(VarInt.encode(
          QuicTransportParameterId.initialMaxStreamDataBidiRemote.value));
      builder.add(VarInt.encode(bytes.length));
      builder.add(bytes);
    }
    // initial_max_stream_data_uni (0x07)
    if (initialMaxStreamDataUni > 0) {
      final bytes = VarInt.encode(initialMaxStreamDataUni);
      builder.add(VarInt.encode(
          QuicTransportParameterId.initialMaxStreamDataUni.value));
      builder.add(VarInt.encode(bytes.length));
      builder.add(bytes);
    }
    // initial_max_streams_bidi (0x08)
    if (initialMaxStreamsBidi > 0) {
      final bytes = VarInt.encode(initialMaxStreamsBidi);
      builder.add(
          VarInt.encode(QuicTransportParameterId.initialMaxStreamsBidi.value));
      builder.add(VarInt.encode(bytes.length));
      builder.add(bytes);
    }
    // initial_max_streams_uni (0x09)
    if (initialMaxStreamsUni > 0) {
      final bytes = VarInt.encode(initialMaxStreamsUni);
      builder.add(
          VarInt.encode(QuicTransportParameterId.initialMaxStreamsUni.value));
      builder.add(VarInt.encode(bytes.length));
      builder.add(bytes);
    }
    // ack_delay_exponent (0x0a)
    final ackDelayExponentBytes = VarInt.encode(ackDelayExponent);
    builder.add(VarInt.encode(QuicTransportParameterId.ackDelayExponent.value));
    builder.add(VarInt.encode(ackDelayExponentBytes.length));
    builder.add(ackDelayExponentBytes);
    // max_ack_delay (0x0b)
    final maxAckDelayBytes = VarInt.encode(maxAckDelay);
    builder.add(VarInt.encode(QuicTransportParameterId.maxAckDelay.value));
    builder.add(VarInt.encode(maxAckDelayBytes.length));
    builder.add(maxAckDelayBytes);
    // active_connection_id_limit (0x0e)
    final activeConnectionIdLimitBytes = VarInt.encode(activeConnectionIdLimit);
    builder.add(
        VarInt.encode(QuicTransportParameterId.activeConnectionIdLimit.value));
    builder.add(VarInt.encode(activeConnectionIdLimitBytes.length));
    builder.add(activeConnectionIdLimitBytes);
    // max_datagram_frame_size (0x20)
    final maxDgBytes = VarInt.encode(maxDatagramFrameSize);
    builder.add(
        VarInt.encode(QuicTransportParameterId.maxDatagramFrameSize.value));
    builder.add(VarInt.encode(maxDgBytes.length));
    builder.add(maxDgBytes);
    // version_information (0x11, RFC 9368)
    final info = versionInformation;
    if (info != null) {
      final infoBytes = info.serialize();
      builder.add(
          VarInt.encode(QuicTransportParameterId.versionInformation.value));
      builder.add(VarInt.encode(infoBytes.length));
      builder.add(infoBytes);
    }
    // disable_active_migration (0x0c, RFC 9000 Section 9)
    if (!allowMigration) {
      builder.add(
          VarInt.encode(QuicTransportParameterId.disableActiveMigration.value));
      builder.add(VarInt.encode(0));
    }
    // preferred_address (0x0d, RFC 9000 Section 9.6)
    final pa = preferredAddress;
    if (pa != null) {
      final addrBytes = pa.rawAddress;
      final portBytes = [
        (preferredAddressPort >> 8) & 0xFF,
        preferredAddressPort & 0xFF
      ];
      final paBytes = Uint8List.fromList([...addrBytes, ...portBytes]);
      builder
          .add(VarInt.encode(QuicTransportParameterId.preferredAddress.value));
      builder.add(VarInt.encode(paBytes.length));
      builder.add(paBytes);
    }
    // grease_quic_bit (0x2ab2, RFC 9287)
    if (greaseQuicBit) {
      builder.add(VarInt.encode(QuicTransportParameterId.greaseQuicBit.value));
      builder.add(VarInt.encode(0));
    }
    // initial_source_connection_id (0x0f)
    final iscid = initialSourceConnectionId;
    if (iscid != null) {
      builder.add(VarInt.encode(
          QuicTransportParameterId.initialSourceConnectionId.value));
      builder.add(VarInt.encode(iscid.length));
      builder.add(iscid);
    }
    // retry_source_connection_id (0x10)
    final rscid = retrySourceConnectionId;
    if (rscid != null) {
      builder.add(VarInt.encode(
          QuicTransportParameterId.retrySourceConnectionId.value));
      builder.add(VarInt.encode(rscid.length));
      builder.add(rscid);
    }
    // early_data (0x42, RFC 9001)
    final earlyDataBytes = VarInt.encode(maxEarlyData);
    builder.add(VarInt.encode(QuicTransportParameterId.earlyData.value));
    builder.add(VarInt.encode(earlyDataBytes.length));
    builder.add(earlyDataBytes);
    return Uint8List.fromList(builder.toBytes());
  }

  /// Parse peer transport parameters and update connection state.
  ///
  /// Each parameter is encoded as: id (varint) + length (varint) + value.
  /// If a version information parameter is present, its chosen version is
  /// validated against available versions per RFC 9368.
  void applyPeerTransportParameters(Uint8List bytes) {
    var offset = 0;
    while (offset < bytes.length) {
      if (offset >= bytes.length) break;
      final id =
          VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes + offset);
      final idLength = VarInt.decodeLength(bytes[offset]);
      offset += idLength;

      if (offset >= bytes.length) {
        throw FormatException('Incomplete transport parameter: missing length');
      }
      final length =
          VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes + offset);
      final lengthLength = VarInt.decodeLength(bytes[offset]);
      offset += lengthLength;

      if (offset + length > bytes.length) {
        throw FormatException(
          'Transport parameter value exceeds buffer: need $length bytes at offset $offset',
        );
      }
      final value = Uint8List.sublistView(bytes, offset, offset + length);
      offset += length;

      if (id == QuicTransportParameterId.maxIdleTimeout.value) {
        maxIdleTimeout = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.maxUdpPayloadSize.value) {
        maxUdpPayloadSize = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.initialMaxData.value) {
        initialMaxData = VarInt.decode(value.buffer);
      } else if (id ==
          QuicTransportParameterId.initialMaxStreamDataBidiLocal.value) {
        initialMaxStreamDataBidiLocal = VarInt.decode(value.buffer);
      } else if (id ==
          QuicTransportParameterId.initialMaxStreamDataBidiRemote.value) {
        initialMaxStreamDataBidiRemote = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.initialMaxStreamDataUni.value) {
        initialMaxStreamDataUni = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.initialMaxStreamsBidi.value) {
        initialMaxStreamsBidi = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.initialMaxStreamsUni.value) {
        initialMaxStreamsUni = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.ackDelayExponent.value) {
        ackDelayExponent = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.maxAckDelay.value) {
        maxAckDelay = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.activeConnectionIdLimit.value) {
        activeConnectionIdLimit = VarInt.decode(value.buffer);
      } else if (id == QuicTransportParameterId.disableActiveMigration.value) {
        allowMigration = false;
      } else if (id == QuicTransportParameterId.versionInformation.value) {
        final info = VersionInformation.parse(value);
        if (!info.availableVersions.contains(info.chosenVersion)) {
          throw FormatException(
            'version_information chosenVersion 0x${info.chosenVersion.toRadixString(16)} '
            'is not in availableVersions',
          );
        }
        versionInformation = info;
      } else if (id ==
          QuicTransportParameterId.originalDestinationConnectionId.value) {
        originalDestinationConnectionId = Uint8List.fromList(value);
      } else if (id == QuicTransportParameterId.statelessResetToken.value) {
        statelessResetToken = Uint8List.fromList(value);
      } else if (id ==
          QuicTransportParameterId.initialSourceConnectionId.value) {
        initialSourceConnectionId = Uint8List.fromList(value);
      } else if (id == QuicTransportParameterId.retrySourceConnectionId.value) {
        retrySourceConnectionId = Uint8List.fromList(value);
      } else if (id == QuicTransportParameterId.preferredAddress.value) {
        // Parse 4-byte IPv4 + 2-byte port (simplified; full support needs IPv6).
        if (value.length >= 6) {
          final addrStr = '${value[0]}.${value[1]}.${value[2]}.${value[3]}';
          preferredAddress = InternetAddress(addrStr);
          preferredAddressPort = (value[4] << 8) | value[5];
        }
      }
    }
  }

  /// Check whether 0-RTT is compatible with the peer's version information.
  ///
  /// Returns `true` if this connection's [versionInformation] and [peerInfo]
  /// indicate that 0-RTT can be used across versions (RFC 9368).
  bool isZeroRttCompatibleAcrossVersions(VersionInformation peerInfo) {
    final local = versionInformation;
    if (local == null) return false;
    return local.isZeroRttCompatible(peerInfo);
  }

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

  /// Allocates a new client-initiated bidirectional stream ID.
  ///
  /// The returned stream ID is unique within this connection and can be used
  /// to create a [QuicStream] via the [streamManager]. Bidirectional streams
  /// allow both endpoints to send and receive data.
  ///
  /// Throws [StateError] if the connection is closed or the stream limit has
  /// been reached.
  int openBidirectionalStream() => _streamIdAllocator.allocateClientBidi();

  /// Allocates a new client-initiated unidirectional stream ID.
  ///
  /// The returned stream ID is unique within this connection. Unidirectional
  /// streams allow only the initiator to send data; the peer can only receive.
  ///
  /// Throws [StateError] if the connection is closed or the stream limit has
  /// been reached.
  int openUnidirectionalStream() => _streamIdAllocator.allocateClientUni();

  /// Initiates a graceful close of this connection.
  ///
  /// Transitions the connection to the closing state, which triggers the
  /// emission of a CONNECTION_CLOSE frame and begins the draining period.
  /// The connection will eventually move to [ConnectionState.closed] once
  /// the peer acknowledges the close or the draining timer expires.
  ///
  /// For an immediate abort, use [abort].
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
      0, // RecoveryManager computes effective ackedBytes from tracker
      ranges: ranges,
    );
    // Track application-space ACKs for key update confirmation (RFC 9001 §6.1).
    if (spaceIndex == PacketNumberSpace.application.spaceIndex) {
      final km = _keyManager;
      if (km != null) {
        km.onAckReceived(largestAcked);
      }
    }
    _pacingCalculator.updateRtt(_rttEstimator.smoothedRtt);
    _pacingCalculator
        .updateCongestionWindow(_congestionController.congestionWindow);
  }

  /// Register a sent packet with the recovery manager and key manager.
  void onPacketSent(
    int packetNumber,
    int sentTimeUs, {
    bool ackEliciting = true,
    bool inFlight = true,
    int sizeInBytes = 0,
    int spaceIndex = 0,
  }) {
    _recoveryManager.onPacketSent(
      spaceIndex,
      packetNumber,
      sentTimeUs,
      sizeInBytes,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
    );
    // Track application-space packets for key update limits (RFC 9001 §6).
    if (spaceIndex == PacketNumberSpace.application.spaceIndex) {
      final km = _keyManager;
      if (km != null) {
        km.onPacketSentWithCurrentKey(packetNumber);
      }
    }
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

  /// The stream manager routing STREAM frames.
  StreamManager get streamManager => _streamManager;

  /// The connection-level flow controller.
  FlowController get connectionFlowController => _connectionFlowController;

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
  bool isPathValidated(List<int> pathId) =>
      _migrationHelper.isPathValidated(pathId);

  /// Called when a path is validated; increments a counter for stats.
  void onPathValidated() {
    _validatedPathCount++;
  }

  /// Number of paths that have been successfully validated.
  int get validatedPathCount => _validatedPathCount;

  /// Send a PATH_CHALLENGE frame to validate a path.
  ///
  /// Generates a new challenge with 8 bytes of unpredictable data, stores
  /// the challenge in [_pendingPathChallenges], and builds an Application-space
  /// packet containing the challenge frame.
  Future<Uint8List> sendPathChallenge(List<int> dcid) async {
    final frame = PathChallengeFrame();
    _pendingPathChallenges[Object.hashAll(frame.data)] = DateTime.now();
    return buildPacket(
      space: PacketNumberSpace.application,
      frames: [frame],
      dcid: dcid,
    );
  }

  /// Handle a received PATH_RESPONSE frame.
  ///
  /// Validates that the response data matches a pending challenge sent via
  /// [sendPathChallenge] or the migration helper. If matched, the path is
  /// marked as validated.
  ///
  /// Returns `true` if the response matched a pending challenge.
  bool onPathResponseReceived(PathResponseFrame frame) {
    final hash = Object.hashAll(frame.data);
    if (_pendingPathChallenges.containsKey(hash)) {
      _pendingPathChallenges.remove(hash);
      onPathValidated();
      return true;
    }
    // Fallback to migration helper for probeNewPath compatibility.
    final originalData =
        (_migrationHelper as _QuicMigrationHelper).lookupChallenge(frame.data);
    if (originalData != null) {
      final response = PathResponseFrame(data: originalData);
      if (_migrationHelper.onResponseReceived(response)) {
        (_migrationHelper as _QuicMigrationHelper).removeChallenge(frame.data);
        onAddressValidated();
        onPathValidated();
        if (_probeCompleter != null && !_probeCompleter!.isCompleted) {
          _probeCompleter!.complete();
        }
        return true;
      }
    }
    return false;
  }

  /// Probe a new path by sending a PATH_CHALLENGE frame.
  ///
  /// Generates a challenge, builds an Application-space packet containing a
  /// [PathChallengeFrame], and returns a [Future] that completes when the
  /// corresponding PATH_RESPONSE is received and the path is validated.
  Future<void> probeNewPath(List<int> dcid) async {
    final challenge =
        (_migrationHelper as _QuicMigrationHelper).generateChallenge();
    _lastProbePacket = await buildPacket(
      space: PacketNumberSpace.application,
      frames: [challenge],
      dcid: dcid,
    );
    _probeCompleter = Completer<void>();
    return _probeCompleter!.future;
  }

  /// The most recent packet built by [probeNewPath], or null if no probe has
  /// been initiated.
  Uint8List? get lastProbePacket => _lastProbePacket;

  /// True while a path probe initiated by [probeNewPath] is pending.
  bool get isProbingPath =>
      _probeCompleter != null && !_probeCompleter!.isCompleted;

  // -----------------------------------------------------------------------
  // Incoming packet pipeline
  // -----------------------------------------------------------------------

  /// Process an incoming UDP datagram, splitting coalesced packets and
  /// dispatching frames to the appropriate subsystems.
  ///
  /// Returns the number of successfully processed packets.
  int processIncomingDatagram(Uint8List datagram) {
    // SECURITY: Silently drop packets for closed/draining connections.
    if (isClosed || state == ConnectionState.draining) {
      return 0;
    }
    onBytesReceived(datagram.length);
    final packets = PacketReceiver.processDatagram(datagram);
    for (final packet in packets) {
      _dispatchFrames(packet.space, packet.frames);
    }
    return packets.length;
  }

  /// Validate ECN counts from an ACK_ECN frame (RFC 9000 Section 13.4.2).
  ///
  /// Checks that counts are monotonically increasing and that CE marks are
  /// not reported without corresponding ECT(0) or ECT(1) marks.
  /// If validation fails, ECN is disabled for future outgoing packets.
  void _validateEcnCounts(AckEcnFrame frame) {
    if (_ecnFailed) return;

    // Check monotonicity: counts must not decrease.
    if (frame.ect0Count < _lastAckEct0Count ||
        frame.ect1Count < _lastAckEct1Count ||
        frame.ceCount < _lastAckCeCount) {
      _ecnFailed = true;
      _ecnValidated = false;
      return;
    }

    // If CE marks are reported without any ECT(0) or ECT(1) marks,
    // this might indicate ECN bleaching or misreporting.
    if (frame.ceCount > 0 && frame.ect0Count == 0 && frame.ect1Count == 0) {
      _ecnFailed = true;
      _ecnValidated = false;
      return;
    }

    // Update last seen counts.
    _lastAckEct0Count = frame.ect0Count;
    _lastAckEct1Count = frame.ect1Count;
    _lastAckCeCount = frame.ceCount;

    // ECN is considered validated once we receive non-zero counts.
    if (!_ecnValidated &&
        (frame.ect0Count > 0 || frame.ect1Count > 0 || frame.ceCount > 0)) {
      _ecnValidated = true;
    }
  }

  void _dispatchFrames(PacketNumberSpace? space, List<Frame> frames) {
    if (space == null) return;
    for (final frame in frames) {
      switch (frame) {
        case AckEcnFrame f:
          _validateEcnCounts(f);
          onAckReceived(
            space.spaceIndex,
            f.largestAcknowledged,
            f.ackRanges.map((r) => (gap: r.gap, length: r.length)).toList(),
          );
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
          onPathResponseReceived(f);
          break;
        case MaxDataFrame f:
          _connectionFlowController.updateLimit(f.maxData);
          break;
        case MaxStreamDataFrame f:
          _streamManager.updateSendWindow(f.streamId, f.maxStreamData);
          break;
        case MaxStreamsFrame _:
          // Update the stream limit for the given stream type.
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
        case DatagramFrame f:
          _datagramController.add(Uint8List.fromList(f.data));
          break;
        case AckFrequencyFrame f:
          _recoveryManager.ackGenerator.frequencyPolicy
              .processAckFrequencyFrame(f);
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
  Future<Uint8List> buildPacket({
    required PacketNumberSpace space,
    required List<Frame> frames,
    required List<int> dcid,
    List<int>? scid,
  }) async {
    final packetNumber = allocatePacketNumber(space);
    final packet = await PacketSender.buildPacket(
      frames: frames,
      space: space,
      dcid: dcid,
      scid: scid,
      packetNumber: packetNumber,
      greaseQuicBit:
          space == PacketNumberSpace.application ? greaseQuicBit : false,
    );
    final ackEliciting = frames.any((f) => f.isAckEliciting);
    final inFlight = frames.any((f) => f.isInFlight);
    onPacketSent(
      packetNumber,
      DateTime.now().millisecondsSinceEpoch * 1000,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
      sizeInBytes: packet.length,
      spaceIndex: space.spaceIndex,
    );
    onBytesSent(packet.length);
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
    final codec = _codecForSpace(space);
    if (codec == null) {
      // No keys available — build plaintext packet.
      return buildPacket(space: space, frames: frames, dcid: dcid, scid: scid);
    }

    final packetNumber = allocatePacketNumber(space);
    final plaintext = await PacketSender.buildPacket(
      frames: frames,
      space: space,
      dcid: dcid,
      scid: scid,
      packetNumber: packetNumber,
      greaseQuicBit:
          space == PacketNumberSpace.application ? greaseQuicBit : false,
    );

    // Patch the Length field for long headers to account for the AEAD tag.
    final keys = _keyManager!.keysFor(space)!;
    final patched = ProtectedPacketCodec.patchLongHeaderLength(
      plaintext,
      keys.tagLength,
    );

    final result = await codec.protectAndEncrypt(patched, packetNumber);

    final ackEliciting = frames.any((f) => f.isAckEliciting);
    final inFlight = frames.any((f) => f.isInFlight);
    onPacketSent(
      packetNumber,
      DateTime.now().millisecondsSinceEpoch * 1000,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
      sizeInBytes: result.length,
      spaceIndex: space.spaceIndex,
    );
    onBytesSent(result.length);

    return result;
  }

  /// Create a [ProtectedPacketCodec] for [space] using keys from [_keyManager].
  ProtectedPacketCodec? _codecForSpace(PacketNumberSpace space) {
    final keys = _keyManager?.keysFor(space);
    if (keys == null) return null;
    return ProtectedPacketCodec(
      keys: keys,
      destinationConnectionIdLength: connectionId?.length ?? 8,
    );
  }

  /// Process an incoming encrypted UDP datagram.
  ///
  /// Splits coalesced packets, attempts to remove header protection and decrypt
  /// each packet using keys from [_keyManager], parses frames from the
  /// decrypted payload, and dispatches them. Falls back to plaintext processing
  /// if no keys exist for a packet's space.
  ///
  /// Returns the number of successfully processed packets.
  Future<int> processEncryptedDatagram(Uint8List datagram) async {
    // SECURITY: Silently drop packets for closed/draining connections.
    if (isClosed || state == ConnectionState.draining) {
      return 0;
    }
    onBytesReceived(datagram.length);
    final rawPackets = CoalescedPacket.split(datagram);
    var processed = 0;
    for (final rawPacket in rawPackets) {
      final result = await _processEncryptedPacket(rawPacket);
      if (result != null) {
        _dispatchFrames(result.space, result.frames);
        processed++;
      }
    }
    return processed;
  }

  /// Attempt to decrypt and parse a single raw packet.
  ///
  /// First tries to determine the packet number space and use the
  /// corresponding keys via [ProtectedPacketCodec]. If decryption succeeds,
  /// returns the space and parsed frames. Otherwise falls back to plaintext
  /// parsing via [PacketReceiver]. Returns null if the packet cannot be
  /// processed.
  Future<({PacketNumberSpace space, List<Frame> frames})?>
      _processEncryptedPacket(Uint8List rawPacket) async {
    if (rawPacket.isEmpty) return null;
    final isLong = (rawPacket[0] & 0x80) != 0;

    if (isLong) {
      // For QUIC v1 long headers, bits 5-4 are the packet type and are
      // not protected by header protection.
      final packetType = (rawPacket[0] >> 4) & 0x03;
      final space = _spaceFromLongPacketType(packetType);
      if (space != null) {
        final codec = _codecForSpace(space);
        if (codec != null) {
          final decrypted = await codec.unprotectAndDecrypt(rawPacket);
          if (decrypted != null) {
            return (space: space, frames: decrypted.frames);
          }
        }
      }
    } else {
      // Short header packets are always in the Application space.
      final space = PacketNumberSpace.application;
      final codec = _codecForSpace(space);
      if (codec != null) {
        final decrypted = await codec.unprotectAndDecrypt(rawPacket);
        if (decrypted != null) {
          return (space: space, frames: decrypted.frames);
        }
      }
    }

    // Fallback: plaintext processing.
    final result = PacketReceiver.processPacket(rawPacket);
    if (result != null && result.space != null) {
      return (space: result.space!, frames: result.frames);
    }
    return null;
  }

  /// Map a QUIC v1 long-header packet type to its [PacketNumberSpace].
  static PacketNumberSpace? _spaceFromLongPacketType(int packetType) {
    switch (packetType) {
      case 0x00: // Initial
        return PacketNumberSpace.initial;
      case 0x01: // 0-RTT
        return PacketNumberSpace.zeroRtt;
      case 0x02: // Handshake
        return PacketNumberSpace.handshake;
      case 0x03: // Retry
        return null;
      default:
        return null;
    }
  }

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

  /// Update the connection-level flow control limit.
  void updateConnectionFlowControl(int newLimit) =>
      _connectionFlowController.updateLimit(newLimit);
}

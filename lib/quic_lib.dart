/// A comprehensive, pure-Dart implementation of the QUIC protocol stack.
///
/// **quic_lib** provides a fully Dart-native networking stack covering four
/// major subsystems built on top of each other:
///
/// 1. **QUIC transport** — RFC 9000/9001/9002 compliant wire format, packet
///    protection, handshake, stream multiplexing, flow control, congestion
///    control, and connection migration.
/// 2. **HTTP/3** — RFC 9114 mapping of HTTP semantics onto QUIC streams with
///    QPACK header compression.
/// 3. **WebTransport** — RFC 9220 datagram and stream sessions over HTTP/3.
/// 4. **libp2p QUIC** — Transport, multiaddr parsing, and PeerId handling for
///    libp2p networks.
///
/// ## Quick start
///
/// Import the full public API in one line:
///
/// ```dart
/// import 'package:quic_lib/quic_lib.dart';
/// ```
///
/// Create an endpoint, connect to a peer, and open a bidirectional stream:
///
/// ```dart
/// import 'dart:io';
/// import 'dart:typed_data';
/// import 'package:quic_lib/quic_lib.dart';
///
/// Future<void> main() async {
///   final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
///   final connection = await endpoint.connect(
///     InternetAddress.loopbackIPv4,
///     4433,
///   );
///
///   final streamId = connection.openBidirectionalStream();
///   final frame = StreamFrame(
///     streamId: streamId,
///     data: Uint8List.fromList([1, 2, 3]),
///     fin: true,
///   );
///   // Packetize and send via PacketSender...
///
///   connection.close();
///   endpoint.close();
/// }
/// ```
///
/// ## Subsystem barrel files
///
/// If you only need a subset of the API, import one of the focused barrel
/// files instead:
///
/// | Barrel file | Exports |
/// |-------------|---------|
/// | `quic_lib.dart` | **Everything** — wire format, crypto, connection, streams, recovery, HTTP/3, WebTransport, libp2p |
/// | `quic.dart` | QUIC transport core only — endpoint, connection, stream scheduler, isolates |
/// | `http3.dart` | HTTP/3 layer — connection, request, response, frames, QPACK |
/// | `webtransport.dart` | WebTransport sessions, capsules, and stream types |
/// | `libp2p.dart` | libp2p transport — multiaddr, peer IDs, QUIC dial/listen |
///
/// See also:
/// * `quic.dart` — QUIC transport only.
/// * `http3.dart` — HTTP/3 client and server.
/// * `webtransport.dart` — WebTransport sessions.
/// * `libp2p.dart` — libp2p QUIC transport.
library quic_lib;

// ---------------------------------------------------------------------------
// Wire format exports
// ---------------------------------------------------------------------------
export 'src/wire/varint.dart' show VarInt;

export 'src/wire/packet_header.dart'
    show
        PacketHeader,
        LongHeader,
        ShortHeader,
        VersionNegotiationPacket,
        PacketHeaderParser;

export 'src/wire/frame.dart'
    show
        Frame,
        PaddingFrame,
        PingFrame,
        AckFrame,
        AckRange,
        AckEcnFrame,
        AckFrequencyFrame,
        DatagramFrame,
        ResetStreamFrame,
        StopSendingFrame,
        CryptoFrame,
        NewTokenFrame,
        StreamFrame,
        MaxDataFrame,
        MaxStreamDataFrame,
        MaxStreamsFrame,
        DataBlockedFrame,
        StreamDataBlockedFrame,
        StreamsBlockedFrame,
        NewConnectionIdFrame,
        RetireConnectionIdFrame,
        PathChallengeFrame,
        PathResponseFrame,
        ConnectionCloseFrame,
        ApplicationCloseFrame,
        HandshakeDoneFrame,
        FrameCodec;

export 'src/wire/packet_number.dart' show PacketNumber;
export 'src/wire/packet_builder.dart' show PacketBuilder;
export 'src/wire/coalesced_packet.dart' show CoalescedPacket;
export 'src/wire/retry_packet_builder.dart' show RetryPacketBuilder;
export 'src/wire/stateless_reset_generator.dart' show StatelessResetGenerator;
export 'src/wire/v2_header.dart' show V2LongHeader;
export 'src/wire/quic_versions.dart' show QuicVersions;
export 'src/wire/quic_bit_greaser.dart' show QuicBitGreaser;

// ---------------------------------------------------------------------------
// Crypto exports
// ---------------------------------------------------------------------------
export 'src/crypto/crypto_backend.dart'
    show
        CryptoBackend,
        SecretKey,
        PublicKey,
        KeyPair,
        AeadAlgorithm,
        HashAlgorithm,
        AeadResult;

export 'src/crypto/default_crypto_backend.dart' show DefaultCryptoBackend;

export 'src/crypto/cipher_suites.dart'
    show Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Sha256, Sha384;

export 'src/crypto/initial_secrets.dart' show InitialSecrets;
export 'src/crypto/packet/packet_protector.dart' show PacketProtector;
export 'src/crypto/packet/header_protection.dart' show HeaderProtection;
export 'src/crypto/packet/nonce_generator.dart' show NonceGenerator;
export 'src/crypto/packet/key_derivation.dart' show KeyDerivation;
export 'src/crypto/packet/key_update.dart' show KeyUpdate;
export 'src/crypto/packet/retry_integrity_tag.dart' show RetryIntegrityTag;
export 'src/crypto/zero_rtt_helper.dart' show ZeroRttHelper;

// ---------------------------------------------------------------------------
// TLS exports
// ---------------------------------------------------------------------------
export 'src/crypto/tls/tls_handshake_types.dart'
    show
        TlsHandshakeType,
        TlsContentType,
        TlsExtensionType,
        QuicTransportParameterId,
        TlsConstants;

export 'src/crypto/tls/new_session_ticket.dart' show NewSessionTicket;

export 'src/crypto/tls/client_hello.dart'
    show ClientHello, CipherSuite, TlsExtension;
export 'src/crypto/tls/server_hello.dart' show ServerHello;
export 'src/crypto/tls/encrypted_extensions.dart' show EncryptedExtensions;
export 'src/crypto/tls/certificate_message.dart'
    show CertificateMessage, CertificateEntry;
export 'src/crypto/tls/certificate_verify.dart' show CertificateVerify;
export 'src/crypto/tls/finished_message.dart' show FinishedMessage;
export 'src/crypto/tls/handshake_state_machine.dart'
    show HandshakeStateMachine, HandshakeState, HandshakeRole;

// ---------------------------------------------------------------------------
// Connection exports
// ---------------------------------------------------------------------------
export 'src/connection/connection_state_machine.dart'
    show ConnectionStateMachine, ConnectionState;

export 'src/connection/connection_id_manager.dart'
    show ConnectionIdManager, ConnectionIdRecord;

export 'src/connection/connection_registry.dart' show ConnectionRegistry;
export 'src/connection/migration_helper.dart' show MigrationHelper;
export 'src/connection/quic_connection.dart' show QuicConnection;
export 'src/connection/version_information.dart' show VersionInformation;
export 'src/connection/congestion_control/cubic.dart'
    show CubicCongestionController;
export 'src/connection/packet_receiver.dart' show PacketReceiver;
export 'src/connection/packet_sender.dart' show PacketSender;
export 'src/recovery/packet_number_space.dart'
    show PacketNumberSpace, PacketNumberSpaceManager;

export 'src/io/udp_socket.dart' show UdpSocket;
export 'src/io/quic_endpoint.dart' show QuicEndpoint;
export 'src/io/connection_isolate.dart' show ConnectionIsolate;
export 'src/io/isolate_supervisor.dart' show IsolateSupervisor;

// ---------------------------------------------------------------------------
// Stream exports
// ---------------------------------------------------------------------------
export 'src/streams/stream_id.dart' show StreamId, StreamIdAllocator;
export 'src/streams/stream_scheduler.dart' show StreamScheduler;
export 'src/streams/round_robin_scheduler.dart' show RoundRobinScheduler;
export 'src/streams/send_state_machine.dart'
    show SendStateMachine, SendStreamState;

export 'src/streams/receive_state_machine.dart'
    show ReceiveStateMachine, ReceiveStreamState;

export 'src/streams/reassembly_buffer.dart' show ReassemblyBuffer;
export 'src/streams/flow_controller.dart' show FlowController;
export 'src/streams/quic_stream.dart'
    show QuicStream, QuicSendStream, QuicReceiveStream;

// ---------------------------------------------------------------------------
// Recovery exports
// ---------------------------------------------------------------------------
export 'src/recovery/rtt_estimator.dart' show RttEstimator;
export 'src/recovery/loss_detector.dart' show LossDetector;
export 'src/recovery/pto_scheduler.dart' show PtoScheduler;
export 'src/recovery/congestion_controller.dart' show CongestionController;
export 'src/recovery/pacing_calculator.dart' show PacingCalculator;
export 'src/recovery/sent_packet_tracker.dart'
    show SentPacketTracker, SentPacketInfo;
export 'src/recovery/ack_generator.dart' show AckGenerator;

// ---------------------------------------------------------------------------
// HTTP/3 exports
// ---------------------------------------------------------------------------
export 'src/http3/qpack_integer.dart' show QpackInteger;
export 'src/http3/qpack_string.dart' show QpackString;
export 'src/http3/qpack_static_table.dart'
    show QpackStaticTable, QpackStaticTableEntry;
export 'src/http3/qpack_decoder.dart' show QpackDecoder, QpackFieldLine;
export 'src/http3/qpack_encoder.dart' show QpackEncoder;

export 'src/http3/frame_types.dart' show Http3FrameType, Http3Frame;
export 'src/http3/settings_frame.dart' show Http3SettingsFrame, Http3SettingsId;
export 'src/http3/goaway_frame.dart' show Http3GoawayFrame;
export 'src/http3/cancel_push_frame.dart' show Http3CancelPushFrame;
export 'src/http3/push_promise_frame.dart' show Http3PushPromiseFrame;
export 'src/http3/headers_frame.dart' show Http3HeadersFrame;
export 'src/http3/http3_stream.dart' show Http3StreamHandler, Http3StreamType;

// ---------------------------------------------------------------------------
// WebTransport exports
// ---------------------------------------------------------------------------
export 'src/webtransport/capsule_types.dart' show CapsuleType, Capsule;
export 'src/webtransport/stream_types.dart'
    show WebTransportStreamId, WebTransportStreamType;

export 'src/webtransport/webtransport_session.dart' show WebTransportSession;
export 'src/webtransport/webtransport_session_manager.dart'
    show WebTransportSessionManager;

// ---------------------------------------------------------------------------
// libp2p exports
// ---------------------------------------------------------------------------
export 'src/libp2p/multiaddr.dart' show Multiaddr, MultiaddrComponent;
export 'src/libp2p/peer_id.dart' show PeerId;
export 'src/libp2p/libp2p_quic_transport.dart'
    show Libp2pQuicTransport, Libp2pQuicConnection;
export 'src/libp2p/dcutr_state_machine.dart' show DCUtRStateMachine;
export 'src/libp2p/multistream_select.dart' show MultistreamSelect;
export 'src/libp2p/libp2p_tls_extension.dart' show SignedKey, Libp2pExtension;
export 'src/libp2p/libp2p_certificate_generator.dart'
    show Libp2pCertificateGenerator;

// ---------------------------------------------------------------------------
// Congestion control exports
// ---------------------------------------------------------------------------
export 'src/connection/congestion_control/bbr.dart'
    show BbrCongestionController, BbrState;
export 'src/connection/congestion_control/hystart.dart' show Hystart;

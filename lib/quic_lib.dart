/// Public API barrel file for quic_lib.
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
    show TlsHandshakeType, TlsContentType, TlsExtensionType, TlsConstants;

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
export 'src/connection/packet_receiver.dart' show PacketReceiver;
export 'src/connection/packet_sender.dart' show PacketSender;
export 'src/recovery/packet_number_space.dart'
    show PacketNumberSpace, PacketNumberSpaceManager;

export 'src/io/udp_socket.dart' show UdpSocket;
export 'src/io/quic_endpoint.dart' show QuicEndpoint;

// ---------------------------------------------------------------------------
// Stream exports
// ---------------------------------------------------------------------------
export 'src/streams/stream_id.dart' show StreamId, StreamIdAllocator;
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

// ---------------------------------------------------------------------------
// libp2p exports
// ---------------------------------------------------------------------------
export 'src/libp2p/multiaddr.dart' show Multiaddr, MultiaddrComponent;
export 'src/libp2p/peer_id.dart' show PeerId;

# Changelog

All notable changes to `quic_lib` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.7.0] — 2026-06-29

### Added
- **QPACK encoder/decoder streams (RFC 9204 Section 4.2)** — `Http3Connection` now owns a `QpackEncoder` and `QpackDecoder`, opens QPACK unidirectional streams, and flushes encoder/decoder instructions.
- Dynamic table insertions from `QpackEncoder` are emitted as encoder-stream instructions and can be sent via `flushQpackEncoderInstructions()`.
- Received encoder-stream instructions update the decoder's dynamic table; received decoder-stream instructions update the encoder's known received count.
- `Http3Response.getResponse()` now emits a `SectionAcknowledgment` decoder instruction per decoded header block.
- Added `Http3SettingsFrame` convenience getters for `maxFieldSectionSize`, `maxTableCapacity`, and `blockedStreams`.

### Changed
- `Http3Request.encodeHeaders`, `Http3Response.encodeHeaders`, and `ExtendedConnectRequest.encodeHeaders` accept an optional `QpackEncoder` for dynamic table usage.
- `Http3Response.decodeHeaders` accepts an optional `QpackDecoder`.
- `Http3Connection` initializes the decoder dynamic table capacity from local SETTINGS.

### Tests
- Added `test/http3/qpack_stream_integration_test.dart` covering stream opening, instruction flushing, and instruction parsing for both encoder and decoder streams.

---

## [1.6.0] — 2026-06-29

### Added
- **Packet pacing enforcement (RFC 9002 §7.7)** — added `PacingTimer` and wired it into `QuicConnection.buildPacket` / `buildEncryptedPacket`. Pacing is now enforced with a synchronous delay when the congestion window exceeds the burst threshold; ACK-only packets are skipped as recommended by the RFC.

### Changed
- **Tests** — added `test/recovery/pacing_timer_test.dart` and expanded `test/recovery/pacing_integration_test.dart` with enforcement tests.

---

## [1.5.0] — 2026-06-29

### Added
- **Peer-initiated key update detection (RFC 9001 §6.2)** — `QuicConnection` now detects key updates initiated by the peer via the 1-RTT key phase bit and updates local send keys to match
- **Proactive next-generation key derivation** — `KeyManager` derives next-generation receive and send keys ahead of time to avoid timing side-channels when a peer update is detected
- **Packet-number-based key selection** — `KeyManager.receiveKeysForPhase()` selects previous vs. next-generation keys based on packet number, supporting reordered packets and preventing rollback to old keys for high packet numbers (RFC 9001 §6.5)
- **Header protection key stability** — the header protection key is now reused across key updates as required by RFC 9001 §5.4
- **Non-monotonic key update protection** — `KeyManager.onPeerKeyUpdateDetected()` rejects packet numbers that would roll back key phase and prevents a second key update before the previous one is acknowledged
- **Key update completion signaling** — `QuicConnection.onPacketSent` confirms a peer-initiated key update on the first application-space send; old keys are discarded via `KeyManager.confirmKeyUpdate()` or after a 3×PTO deadline
- **Initial packet padding** — `PacketBuilder.build` pads client Initial packets to at least 1200 bytes per RFC 9000 Section 14.1; `FrameCodec` coalesces consecutive PADDING bytes into a single frame
- **0-RTT early-data flag** — `QuicStream` exposes `isEarlyData`; `StreamManager` sets it for receive streams from 0-RTT packets and `QuicConnection` sets it for send streams opened while 0-RTT keys are available; `PacketReceiver` now maps 0-RTT headers to `PacketNumberSpace.zeroRtt`
- **0-RTT key cleanup** — `HandshakeCoordinator.installApplicationKeys` now discards 0-RTT keys once 1-RTT (Application) keys are available, per RFC 9001 §4.1.4
- **Key update completion retention** — a 3×PTO discard deadline is set when a peer-initiated key update is detected so that previous-generation keys remain available for reordered packets (RFC 9001 §6.5); `KeyManager.confirmKeyUpdate` clears the pending flag and may be followed by `maybeDiscardPreviousKeys`

### Changed
- **Tests** — added `test/crypto/peer_key_update_test.dart` and `test/integration/v150_peer_key_update_test.dart` covering peer-initiated detection, simultaneous updates, non-monotonic rollback rejection, key confirmation, and 3×PTO discard; updated `test/wire/packet_builder_test.dart`, `test/connection/zero_rtt_transmission_test.dart`, `test/streams/stream_manager_test.dart`, and `test/connection/packet_receiver_test.dart` for the new behaviors
- **Public API** — `KeyManager.forTest()` remains unchanged; new `KeyManager.forTestWithKeys()` factory provides real derived keys for crypto round-trip tests

---

## [1.4.2] — 2026-06-29

### Fixed
- **RFC 9000 unknown frame handling** — `FrameCodec.parse` now treats unknown frame types as `FRAME_ENCODING_ERROR` per RFC 9000 Section 12.4 (1.4.1 incorrectly ignored them)
- **WebTransport SETTINGS identifiers** — corrected `Http3SettingsId` values per draft-ietf-webtrans-http3-15: `SETTINGS_WT_ENABLED` (0x2c7cf000), `SETTINGS_WT_INITIAL_MAX_DATA` (0x2b61), `SETTINGS_WT_INITIAL_MAX_STREAMS_UNI` (0x2b64), `SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI` (0x2b65)
- **ACK_FREQUENCY frame format** — replaced the incorrect `Ignore Order` boolean with the `Reordering Threshold` varint per RFC 9298
- **ACK_FREQUENCY validation** — `AckFrequencyPolicy.processAckFrequencyFrame()` now validates `requestedMaxAckDelay` (< 2^14 ms and >= `min_ack_delay`) and `requestedAckElicitingThreshold` (non-negative) per RFC 9298
- **Key update confirmation** — `KeyManager` now verifies that an ACK was received for a packet sent with the current key phase before allowing a subsequent key update, per RFC 9001 §6.1; also tracks lowest packet sent with current key
- **Application-space key update wiring** — `QuicConnection.onPacketSent()` and `onAckReceived()` now notify `KeyManager` for 1-RTT packets
- **Capsule size limits** — `Capsule.parse()` rejects capsule payloads larger than 1 MiB to prevent DoS via memory exhaustion
- **DATAGRAM frame size limits** — `FrameCodec.parse()` now enforces a 1 MiB defensive upper bound on DATAGRAM frame payloads (types 0x30/0x31) to prevent excessive memory allocation from malicious length fields
- **Public API exports** — `http3.dart` now exports `RegisterBidirectionalStreamCapsule`, `RegisterUnidirectionalStreamCapsule`, `WtMaxStreamsCapsule`, `WtMaxDataCapsule`, `WtMaxStreamDataCapsule`, and `UnknownCapsule`; `quic_lib.dart` now exports `AckFrequencyPolicy` and `KeyManager`

### Changed
- **Tests** — updated all `ACK_FREQUENCY`, `KeyManager`, and WebTransport settings tests to match the corrected RFC behavior

---

## [1.4.1] — 2026-06-29

### Added
- **RFC 9000 transport error codes** — `QuicTransportErrorCode` enum defines all 17 standard error codes (0x00–0x10) per RFC 9000 Section 20.1; includes `fromValue()` lookup helper
- **WebTransport SETTINGS parameters** — `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` (0x2b60) and `SETTINGS_WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI` (0x14e9cd29) added to `Http3SettingsId`
- **WebTransport flow control capsules** — `WtMaxStreamsCapsule`, `WtMaxDataCapsule`, and `WtMaxStreamDataCapsule` implement draft-ietf-webtrans-http3 §5.6 flow control
- **ACK_FREQUENCY receiver processing** — `AckFrequencyPolicy` tracks peer-requested ACK parameters; `AckGenerator` integrates threshold-based ACK triggering per RFC 9298 §6
- **Key update tracking** — `KeyManager` now tracks packet counts, initiates key updates on confidentiality limit, and manages key phase confirmation per RFC 9001 §6
- **Unknown capsule handling** — `UnknownCapsule` class preserves unknown capsule types instead of throwing

### Fixed
- **Unknown frame handling** — `FrameCodec.parse` now silently ignores unknown extension frames per RFC 9000 Section 19.21 instead of throwing `UnsupportedError`

---

## [1.4.0] — 2026-06-29

### Added
- **BBR congestion control** — `BbrCongestionController` implements Bottleneck Bandwidth and RTT (BBR) congestion control algorithm; exported in `lib/quic.dart` and `lib/quic_lib.dart`
- **Hystart** — `Hystart` exported from `lib/quic.dart` and `lib/quic_lib.dart` for slow-start exit heuristic (RFC 8312 Appendix B)
- **ACK_FREQUENCY frame (RFC 9298)** — `AckFrequencyFrame` with `sequenceNumber`, `requestedAckElicitingThreshold`, `requestedMaxAckDelay`, and `ignoreOrder` fields; serialize/parse support in `frame.dart`
- **ACK range tracking** — `AckGenerator` implements ACK range tracking per RFC 9000 Section 13.2.1
- **Persistent congestion detection** — Implemented per RFC 9002 Section 7.6
- **App-limited detection** — Implemented per RFC 9002 Section 7.3
- **Missing transport parameters** — Added `original_destination_connection_id`, `stateless_reset_token`, `initial_source_connection_id`, `retry_source_connection_id`, and `preferred_address` parsing in `applyPeerTransportParameters`
- **WebTransport bidirectional/unidirectional stream capsules** — `REGISTER_BIDIRECTIONAL_STREAM` (0x41) and `REGISTER_UNIDIRECTIONAL_STREAM` (0x54) capsules with serialize/parse
- **ALPN in libp2p TLS handshake** — Wired ALPN negotiation and validation into `libp2p_quic_transport.dart` TLS handshake

### Fixed
- **HTTP/3 SETTINGS frame IDs** — Fixed GREASE values to RFC 9114 pattern (0x40, 0x5f)
- **ORIGIN frame** — Corrected field parsing and serialization to match RFC 9412
- **QPACK encoder indexing** — Fixed static table indexing and post-base index integration into main encoder flow
- **Huffman EOS/padding validation** — `huffman.dart` now validates end-of-stream padding per RFC 7541 Section 5.2
- **CUBIC congestion control RTT handling** — Fixed `CubicCongestionController` to use correct RTT for congestion window calculations
- **Multiaddr error sanitization** — `Multiaddr` and `PeerId` now throw descriptive `FormatException` instead of raw strings
- **HTTP/3 MAX_PUSH_ID handling** — `Http3Connection` now properly receives and dispatches MAX_PUSH_ID frames
- **H3_DATAGRAM guard** — Added frame-processing guards for HTTP/3 datagram frames
- **ECN documentation** — Added inline RFC 9000 Section 13.4 references throughout recovery layer
- **WebTransport capsule type values** — Fixed `CLOSE_WEBTRANSPORT_SESSION` to correct RFC 9220 value (0x2843)
- **Duplicate WebTransportSession** — Consolidated duplicate class definitions into single canonical implementation

### Changed
- `QuicConnection` exposes `congestionController` setter for pluggable congestion control algorithms
- `libp2p.dart` exports `WebTransportSession`, `WebTransportConnectRequest`, `DCUtRMessage`, `DCUtRHandler`, `DCUtRUdpCoordinator`, `MultistreamSelect`, `SignedKey`, `Libp2pExtension`, and `Libp2pCertificateGenerator`

### Tests
- `test/connection/congestion_control/bbr_test.dart` (4 tests)
- `test/connection/congestion_control/hystart_test.dart` (4 tests)
- `test/wire/ack_frequency_frame_test.dart` (5 tests)
- `test/recovery/ack_generator_test.dart` (6 tests)
- `test/connection/version_information_test.dart` (6 tests)

---

## [1.3.0] — 2026-06-28

### Protocol Completeness
- Fixed RFC 9000 errata (8240, 7861, 8410, 7702)
- Implemented RFC 9221 unreliable DATAGRAM frames
- Implemented RFC 9220 Extended CONNECT for WebTransport
- Implemented RFC 9297 HTTP Datagrams + Capsule Protocol
- Implemented RFC 9204 QPACK encoder/decoder stream instructions
- Implemented RFC 9412 ORIGIN frame
- Implemented RFC 9218 PRIORITY_UPDATE frame
- Implemented RFC 9287 QUIC bit greasing
- Implemented RFC 9368 Compatible Version Negotiation
- Implemented ECN processing (RFC 9000 Section 13.4)
- Implemented connection migration with preferred_address transport parameter
- Implemented TLS extensions: SNI, supported_groups, ALPN
- Implemented PSK session resumption (NewSessionTicket)
- Implemented CUBIC congestion control (RFC 8312)
- Implemented libp2p TLS extension with Ed25519 peer authentication
- Implemented libp2p certificate generator
- Implemented multistream-select protocol
- Implemented WebTransport session establishment
- Implemented RFC 7541 static Huffman encoding for QPACK string literals
- Implemented QPACK post-base index representations (RFC 9204 Sections 4.5.3, 4.5.5)
- Added all missing RFC 9000 Section 18.2 transport parameters
- Added HTTP/3 unidirectional stream type identifiers (RFC 9114 Section 6.2)
- Added ECN validation per RFC 9000 Section 13.4.2

---

## [1.2.3] — 2026-06-28

### Platform Support
- **Honest platform declaration** — Removed `web:` from `pubspec.yaml` platforms. `quic_lib` is a native-only package; QUIC requires raw UDP sockets which browsers intentionally block for security reasons (DDoS amplification, port scanning, DNS poisoning).
- **Conditional imports** — Refactored `dart:isolate` and `dart:io` usage to use conditional exports via `dart.library.io`:
  - `ConnectionIsolate` / `IsolateSupervisor` — native implementation + stub for web compilation
  - `UdpSocket` — native `RawDatagramSocket` implementation + web stub
  - `InternetAddress` — abstracted through `platform_address.dart` conditional export
  - `libp2p_quic_transport.dart` and `dcutr_udp_coordinator.dart` updated to use platform address abstraction
- **Documentation** — Added `doc/WEB_AND_WASM.md` explaining why web is unsupported, the browser security model, and recommended alternatives (WebTransport API, WebRTC data channels)

## [1.2.2] — 2026-06-28

### Fixes
- **Static analysis clean** — Fixed 29 `curly_braces_in_flow_control_structures` info issues in `handshake_coordinator.dart`, `frame.dart`, and `packet_header.dart`
- **Removed unnecessary casts** — Fixed `unnecessary_cast` info issues in `default_crypto_backend.dart`
- **Updated dependencies** — Bumped `pointycastle` from `^3.7.0` to `^4.0.0`
- **Example directory** — Added `example/README.md` and `example/pubspec.yaml` for pub.dev example detection

## [1.2.1] — 2026-06-28

### Documentation
- Comprehensive API documentation hardening for pub.dev
- Fixed all 20 dart doc unresolved-reference warnings
- Documented 16 previously undocumented public types with RFC-referenced docs
- Added rich library-level docs with usage examples to all 5 barrel files
- Enhanced README with TOC, feature matrix, platform support, and 4 complete examples
- Added GitHub Actions automated publishing workflow

## [1.2.0] — 2026-06-27

### Security (Security Hardening)
- **Fixed certificate chain verification bug** — `CertificateVerifier` now uses `chain[i+1].publicKey` as issuer key for intermediate certificates instead of always using `trustedRoot`
- **Removed dummy key fallback** — `HandshakeCoordinator._extractX25519PublicKey` throws `StateError` on parse failure instead of falling back to predictable all-zero keys
- **Implemented real X.509 signature verification** — `verifyX509Signature()` delegates to `CryptoBackend` (ed25519/ecdsa/rsa) instead of returning `true`
- **Wired RetryIntegrityTag** — `LongHeader.serialize()` and `V2LongHeader.serialize()` compute real integrity tags for Retry packets using `RetryIntegrityTag.compute()`
- **Real transcript hash in handshake** — `HandshakeCoordinator` uses `_transcriptHash.currentHash` instead of `List<int>.filled(32, 0)` for handshake secret derivation
- **Removed malformed certificate fallback** — `CertificateChain.parseCertificate()` propagates `FormatException` instead of silently accepting synthetic data
- Security tests: `test/crypto/tls/cert_chain_security_test.dart` (4 tests), `test/crypto/tls/handshake_security_test.dart` (3 tests)

### Efficiency (Code Quality)
- **Deleted dead code** — `lib/src/wire/packet_number_reconstructor.dart` (42 lines), `lib/src/crypto/tls/session_ticket_store.dart` (29 lines, duplicate)
- **Extracted shared hex utility** — `lib/src/utils/hex.dart` replaces 4 duplicated `_bytesToHex`/`_encodeKey` implementations
- **Extracted shared list equality** — `lib/src/utils/collections.dart` replaces duplicated `_listEquals`/`_listsEqual` helpers
- **Archived 7 security audit files** — moved to `doc/archive/security_audits/`
- **Consolidated 9 RFC research notes** — merged into `doc/research/RFC_NOTES.md`
- **Consolidated 3 roadmap files** — single `ROADMAP.md` in root
- **Deleted 9 meta-test/coverage-gap test files** — removed meta-tests and coverage gap tests

### Coherence (Architecture)
- **Standardized imports** — `quic_connection.dart` and `quic_endpoint.dart` now use package imports consistently
- **Implemented GOAWAY sending** — `Http3Connection.close()` now calls `_sendGoawayFrame()` instead of leaving a TODO
- **Added frame class docs** — 19 frame classes in `frame.dart` now have RFC 9000 section references
- **Completed public API exports** — `lib/quic.dart`, `lib/http3.dart`, `lib/libp2p.dart`, `lib/webtransport.dart` now export stable public APIs
- **Exported V2LongHeader** — added to `lib/quic_lib.dart` barrel file
- **Completed example scaffolds** — `echo_client.dart` and `echo_server.dart` now demonstrate real API usage
- **Created `doc/README.md`** — explains documentation hierarchy

### Capability (Features)
- **StreamScheduler interface (ADR-006)** — `StreamScheduler` abstract class + `RoundRobinScheduler` implementation; injected into `StreamManager`
- **Isolate-per-connection skeleton (ADR-007)** — `ConnectionIsolate` and `IsolateSupervisor` scaffolds
- **Consolidated body streaming** — merged `http3_body_streaming.dart` into `Http3BodyStream`
- **Version sync** — `pubspec.yaml` updated to `1.2.0` to match CHANGELOG

### Changed
- `PacketHeader.serialize()` returns `Future<Uint8List>` (was `Uint8List`) to support async Retry integrity tag computation
- `PacketBuilder.build()` returns `Future<Uint8List>` (cascade from serialize change)
- `PacketSender.buildPacket()` returns `Future<Uint8List>` (cascade from serialize change)
- `QuicConnection.buildPacket()` and `probeNewPath()` are now `async`
- 23 test files updated to `await` async serialize/build calls

---

## [1.1.0] — 2026-06-27

### Added
- **TLS transcript hash tracking** — `TranscriptHash` maintains a running SHA-256 hash of all handshake messages; `HandshakeCoordinator` adds ClientHello to transcript before shared secret computation
- **HTTP/3 GOAWAY frame sending** — `Http3Connection.close()` creates and records an `Http3GoawayFrame`; `lastAcceptedStreamId` tracks highest stream ID from HEADERS/DATA frames; `hasSentGoaway`/`sentGoawayFrames` getters
- **QUIC v2 long header format** — `V2LongHeader` implements RFC 9369 v2 packet header format with distinct first-byte encoding; full serialize/parse round-trip support for all four packet types
- **WebTransport GOAWAY capsule** — `CapsuleType.goaway(0x1d)`; `GoawayCapsule` with optional `streamId`; `WebTransportSession.receivedGoaway`/`sendGoaway()`
- **Production connection migration scaffold** — `QuicEndpoint.rebindToAddress()` validates new path and updates stored remote address after PATH_CHALLENGE/RESPONSE
- **X.509 certificate parser scaffold** — `X509Certificate` with TBSCertificate, signature, issuer, subject, validity dates, public key info; `parseX509()` validates DER SEQUENCE tag; `verifyX509Signature()` scaffold; wired into `CertificateChain` and `CertificateVerifier`
- Integration tests: `test/crypto/tls/transcript_hash_test.dart` (5 tests), `test/http3/goaway_sending_test.dart` (6 tests), `test/wire/v2_header_test.dart` (13 tests), `test/webtransport/goaway_capsule_test.dart` (3 tests), `test/io/rebind_test.dart` (1 test), `test/crypto/tls/x509_parser_test.dart` (4 tests), `test/integration/post_v100_test.dart` (11 tests)

---

## [1.0.0] — 2026-06-27

### Added
- **PeerId encoding fully wired** — `fromBase58()`, `toBase58()`, `toBase36()` now delegate to the implemented `encodeBase58`/`decodeBase58`/`encodeBase36` methods; no remaining `UnimplementedError` stubs in PeerId
- **HTTP/3 server push scaffold** — `Http3PushPromiseFrame` and `Http3CancelPushFrame` with serialize/parse; `Http3Connection` registers push promises via `registerPushPromise()`/`hasPushPromise()`; `_dispatchFrames` handles pushPromise/cancelPush
- **WebTransport bidirectional streams** — `CapsuleType.registerBidirectionalStream` (0x41) and `registerUnidirectionalStream` (0x42); `StreamCapsule` with serialize/parse; `WebTransportSession` tracks registered bi/uni streams
- **Real TLS handshake coordinator** — `HandshakeCoordinator` wires `HandshakeKeyExchange` into the CRYPTO-frame pipeline: generates ephemeral keys, processes ClientHello key_share, computes shared secret, derives handshake/application traffic secrets; `CryptoFrameHandler` uses coordinator on ClientHello reception
- **Real connection migration** — `QuicEndpoint.changeConnectionAddress()` performs full PATH_CHALLENGE/PATH_RESPONSE protocol over UDP; `QuicConnection.probeNewPath()` generates probe packets and tracks validation via `Completer`; `isProbingPath`/`lastProbePacket` getters
- **QUIC v2 support scaffold** — `QuicVersions` with v1 (0x00000001) and v2 (0x6b3343cf); `PacketReceiver` accepts v2 packets; `VersionNegotiation` includes v2 in supported versions
- **HTTP/3 close scaffold** — `Http3Connection.close()` sets `_isClosing = true`
- Integration tests: `test/libp2p/peer_id_roundtrip_test.dart` (3 tests), `test/http3/push_promise_test.dart` (6 tests), `test/webtransport/stream_capsule_test.dart` (4 tests), `test/crypto/tls/handshake_coordinator_test.dart` (4 tests), `test/connection/path_probing_test.dart` (4 tests), `test/wire/quic_versions_test.dart` (6 tests), `test/integration/v100_features_test.dart` (11 tests)

### Fixed
- `test/libp2p/deep_coverage_test.dart` — updated PeerId Base58/Base36 tests to verify round-trip behavior instead of expecting `UnimplementedError`

---

## [0.5.0] — 2026-06-27

### Added
- **Flow control frame handlers** — `QuicConnection._dispatchFrames` now handles `MAX_DATA` (connection-level), `MAX_STREAM_DATA` (stream-level via `StreamManager`), and `MAX_STREAMS` (scaffold comment); `connectionFlowController` getter exposed
- **HTTP/3 SETTINGS** — `Http3Connection.sendSettings()` returns a default `Http3SettingsFrame` (65536/0/0) instead of throwing `UnimplementedError`; `pendingSettings` getter added
- **PeerId encoding** — `PeerId.encodeBase58()`/`decodeBase58()` and `encodeBase36()`/`decodeBase36()` using standard alphabets
- **Coverage gap closure** — 57 coverage tests (`test/coverage/final_coverage_test.dart`) for FrameCodec.serialize, PacketNumberSpaceManager zeroRtt ops, QuicSend/ReceiveStream, SentPacketTracker, LossDetector, PtoScheduler, ConnectionIdManager, AntiAmplificationLimit
- **Final hardening tests** — 17 security boundary tests (`test/security/final_hardening_test.dart`) for FlowController.maxWindow, ConnectionIdManager.maxActiveIds, AntiAmplificationLimit, SessionTicketStore.maxTickets
- Integration tests: `test/connection/flow_control_frames_test.dart` (4 tests), `test/libp2p/peer_id_encoding_test.dart` (3 tests), `test/integration/v050_features_test.dart` (7 tests)

---

## [0.4.0] — 2026-06-27

### Added
- **TLS certificate chain verification** — `CertificateInfo`, `CertificateChain`, `parseCertificate()` with validity date checks and algorithm filtering; `CertificateVerifier.verifyCertificateChain()` now delegates to `CertificateChain.validateChain()`
- **DCUtR full NAT traversal tests** — `test/libp2p/dcutr_nat_traversal_test.dart` completes a full two-peer UDP hole punch over loopback within 5 seconds; `test/libp2p/dcutr_full_handshake_test.dart` validates Initial → Retry → Initial-with-token packet flow
- **0-RTT early data transmission** — `QuicConnection.canSendZeroRtt`, `buildZeroRttPacket()` builds encrypted 0-RTT packets using derived keys
- **Connection ID rotation** — `QuicConnection.generateNewConnectionIdFrame()`, `activeConnectionIdCount`; `_dispatchFrames` wires `NewConnectionIdFrame` registration and `RetireConnectionIdFrame` retirement via `ConnectionIdManager`
- **Flow control integration** — `StreamManager` creates per-stream `FlowController` instances on first `STREAM` frame; `canSendOnStream()`, `updateSendWindow()`, `getSendFlowController()`, `getReceiveFlowController()`
- **Congestion control pacing integration** — `QuicConnection.pacingCalculator`, `pacingDelayUs`, `shouldPacePackets`; RTT and congestion window updates flow from `onAckReceived()` to `PacingCalculator`
- Integration tests: `test/crypto/tls/certificate_chain_test.dart` (6 tests), `test/libp2p/dcutr_nat_traversal_test.dart` (1 test), `test/libp2p/dcutr_full_handshake_test.dart` (1 test), `test/connection/zero_rtt_transmission_test.dart` (4 tests), `test/connection/connection_id_rotation_test.dart` (3 tests), `test/streams/stream_manager_flow_control_test.dart` (5 tests), `test/recovery/pacing_integration_test.dart` (3 tests), `test/integration/v040_features_test.dart` (5 tests)

### Changed
- `ConnectionIdManager` gained `registerId()` for peer-issued connection IDs
- `_splitHeaderPayload` clamps long-header length to packet size to avoid out-of-bounds on small packets

---

## [0.3.0] — 2026-06-27

### Added
- **DCUtR NAT hole punching** — `DCUtRUdpCoordinator` wires `DCUtRStateMachine` into `UdpSocket` for real UDP-based NAT hole punching with magic-prefixed datagrams
- **0-RTT resumption** — `PacketNumberSpace.zeroRtt` enum value, `KeyManager.deriveZeroRtt()`, `SessionTicketStore` with expiry and max-capacity eviction
- **Full connection migration** — `QuicEndpoint.migrateConnection()`, `QuicConnection.onPathValidated()`, remote address tracking per connection
- **HTTP/3 body streaming** — `Http3BodyStream` with chunk delivery and EOF detection, `Http3Connection.sendBody()`/`getBody()` for DATA frame concatenation
- **TLS certificate verification scaffold** — `CertificateVerifier` with `verifySignature()` dispatching to ed25519/ecdsaP256/rsaPkcs1, `verifyCertificateChain()` structured for future ASN.1/CRL checks
- **Retry token generation** — `RetryTokenGenerator` with HMAC-SHA256 timestamped tokens, expiry validation, and tamper detection
- Integration tests: `test/libp2p/dcutr_udp_coordinator_test.dart` (3 tests), `test/crypto/zero_rtt_test.dart` (9 tests), `test/connection/full_migration_test.dart` (4 tests), `test/http3/http3_body_stream_test.dart` (9 tests), `test/crypto/tls/certificate_verifier_test.dart` (7 tests), `test/crypto/retry_token_generator_test.dart` (5 tests), `test/integration/v030_features_test.dart` (5 tests)

### Changed
- `PacketNumberSpace` enum extended with `zeroRtt(3)`
- `PacketSender.buildPacket` switch handles `PacketNumberSpace.zeroRtt`

---

## [0.2.0] — 2026-06-27

### Added
- **`HandshakeKeyExchange`** — X25519 ephemeral key generation, shared secret computation, and TLS 1.3-style handshake secret derivation (scaffold for real TLS stack)
- **HTTP/3 full request/response** — `Http3Request`/`Http3Response` with QPACK header encoding/decoding, `Http3Connection.sendRequest()` accepts requests, `getResponse()` decodes received HEADERS frames
- **WebTransport datagram support** — `DatagramCapsule` serialize/parse, `CapsuleType.datagram`, `WebTransportSession.sendDatagram()`/`receivedDatagrams`
- **Connection migration wiring** — `MigrationHelper` integrated into `QuicConnection._dispatchFrames()` for `PATH_CHALLENGE`/`PATH_RESPONSE`, `onAddressValidated()` called on successful path validation
- Integration tests: `test/crypto/tls/handshake_key_exchange_test.dart` (4 tests), `test/http3/http3_request_response_test.dart` (7 tests), `test/webtransport/datagram_capsule_test.dart` (3 tests), `test/connection/migration_integration_test.dart` (5 tests), `test/integration/v020_features_test.dart` (12 tests)

### Fixed
- `test/http3/coverage_gap_test.dart` — updated `CapsuleType.fromValue` unknown-value test to use `0x01` instead of `0x00` (now reserved for datagram)

---

## [0.1.0-beta.1] — 2026-06-27

### Added
- **`PacketNumberReconstructor`** — reconstructs full packet numbers from truncated short-header PNs per RFC 9000 §17.1
- **`TlsMessageBuilder`** — constructs structurally valid TLS 1.3 ClientHello, ServerHello, and Finished messages for testing
- **HTTP/3 lifecycle scaffold** in `Http3Connection`: `sendRequest()` allocates streams, `onStreamFrame()` dispatches HEADERS/DATA/SETTINGS/GOAWAY frames
- **`QpackDynamicTable`** — dynamic table insertions, evictions, capacity management, and `encodeWithDynamicTable()` with dynamic→static→literal fallback
- **`CapsuleRouter`** — routes WebTransport capsules to `WebTransportSession` instances by stream ID
- **`DCUtRStateMachine`** — DCUtR handshake state machine (idle → connectSent → syncReceived → connected/failed)
- Integration tests: `test/wire/packet_number_reconstructor_test.dart` (5 tests), `test/crypto/tls/tls_message_builder_test.dart` (6 tests), `test/http3/http3_connection_test.dart` (5 tests), `test/http3/qpack_dynamic_table_test.dart` (11 tests), `test/webtransport/capsule_router_test.dart` (5 tests), `test/libp2p/dcutr_state_machine_test.dart` (14 tests)

---

## [0.1.0-alpha.4] — 2026-06-27

### Added
- **`ProtectedPacketCodec`** — full header protection + AEAD round-trip codec for LongHeader and ShortHeader packets
- **`KeyManager.deriveHandshake()`** and **`.deriveApplication()`** — derive keys for Handshake and Application spaces per RFC 9001 §5.1
- **`KeyManager.discardInitialKeys()`** and **`.discardHandshakeKeys()`** — key lifecycle management per RFC 9001 §4.1.4
- **`CryptoMessageParser`** — parses TLS handshake message type and payload from CRYPTO frame bytes
- **`CryptoFrameHandler`** — wires `CryptoFrameAssembler` → `CryptoMessageParser` → `HandshakeStateMachine.onMessage()`
- **`QuicEndpoint.connect()`** — scaffolds a `QuicConnection` with all subsystems and transitions to handshaking
- Integration tests: `test/crypto/packet/protected_packet_codec_test.dart` (3 tests), `test/crypto/key_manager_test.dart` (5 tests), `test/crypto/tls/crypto_message_parser_test.dart` (8 tests), `test/integration/alpha4_features_test.dart` (10 tests), `test/io/quic_endpoint_connect_test.dart` (4 tests)

### Changed
- `CryptoFrameHandler.onCryptoFrame()` catches invalid state transitions and marks handshake as failed
- `QuicConnection._handleCryptoFrame()` now delegates to `CryptoFrameHandler` when available

---

## [0.1.0-alpha.3] — 2026-06-27

### Added
- **AEAD encryption/decryption wiring** in packet pipeline:
  - `KeyManager` — derives Initial-space keys from DCID using `InitialSecrets` + `KeyDerivation`
  - `PacketNumberSpaceKeys` — holds `PacketProtector` + `HeaderProtection` per space
  - `QuicConnection.buildEncryptedPacket()` — encrypts payload + applies header protection
  - `QuicConnection.processEncryptedDatagram()` — decrypts payload + dispatches frames
  - Falls back to plaintext when no keys are installed
- Integration tests: `test/integration/encrypted_pipeline_test.dart` (6 tests covering key derivation, encrypted build, plaintext fallback, encrypted CRYPTO/STREAM/CONNECTION_CLOSE dispatch)

### Changed
- `QuicConnection` constructor accepts optional `KeyManager`
- `buildPacket` and `processIncomingDatagram` remain as plaintext fallbacks

---

## [0.1.0-alpha.2] — 2026-06-27

### Added
- **Packet pipeline integration** in `QuicConnection`:
  - `processIncomingDatagram()` — splits coalesced packets, dispatches frames to subsystems
  - `buildPacket()` — builds outgoing packets with `PacketSender` and tracks via `RecoveryManager`
  - Frame dispatch: CRYPTO → `CryptoFrameAssembler`, ACK → `RecoveryManager`, STREAM → `StreamManager`, CONNECTION_CLOSE → `ConnectionStateMachine.draining`, HANDSHAKE_DONE → `ConnectionStateMachine.established`
- `StreamManager` — routes STREAM frames to `QuicReceiveStream` instances by stream ID
- `SentPacketTracker.resetAll()` — clears all tracked spaces
- `QuicConnection.stateMachine` public getter
- Integration tests: `test/integration/packet_pipeline_test.dart` (7 tests covering build, ACK dispatch, CRYPTO dispatch, STREAM dispatch, CONNECTION_CLOSE transition, coalesced packets, anti-amplification)

### Changed
- `RecoveryManager.reset()` now calls `_sentPacketTracker.resetAll()`
- CI workflow fuzz/benchmark jobs reference actual scaffold files with realistic timeouts

---

## [0.1.0-alpha.1] — 2026-06-27

### Security
- **36 security fixes** applied across 7 audit loops covering DoS, overflow, replay, info disclosure, timing side channels, and partial frame injection
- Added memory caps on all unbounded collections (ReassemblyBuffer, ConnectionRegistry, MigrationHelper, LossDetector, SentPacketTracker, FlowController, ConnectionIdManager, CryptoFrameAssembler)
- Added integer overflow protection (CongestionController cwnd cap, PtoScheduler ptoCount cap)
- Implemented 64-packet replay window in PacketNumberSpaceManager
- Added ACK validation and clamping in SentPacketTracker
- Added RTT clamping (60s max) and maxAckDelay cap (~16s)
- Added RateLimiter utility for state transition flood protection
- Added anti-amplification limit integration into QuicConnection
- Fixed timing side channels in RetryIntegrityTag.verify and DefaultCryptoBackend.rsaPkcs1Verify
- Fixed partial frame injection vulnerability in PacketReceiver
- Sanitized toString() methods in HTTP/3 frame types to prevent info disclosure via logging

### Added
- `RateLimiter` utility class for sliding-window rate limiting
- `AntiAmplificationLimit` tracker per RFC 9000 Section 8
- `QuicLogger` lightweight logging abstraction (replaces stdout print calls)
- Per-source IP UDP rate limiting in `UdpSocket` (1000 datagrams/sec)
- Integration wiring in `QuicConnection`: `onPacketSent`, `onAckReceived`, `isPtoExpired`, `onPtoFired`, `onAddressValidated`
- Public getters for all `QuicConnection` subsystems (`cidManager`, `rttEstimator`, `lossDetector`, `ptoScheduler`, `congestionController`)

### Changed
- `ConnectionStateMachine` and `WebTransportSession` now use `QuicLogger` instead of `print()`
- `FlowController.consume()` now rejects negative byte counts
- `SentPacketTracker.onAck()` validates space parameter to 0..2
- `PacketNumberSpaceManager.onReceived()` rejects negative packet numbers
- `LossDetector` ignores negative packet numbers and clamps negative `largestAcked`
- `CryptoFrameDeliverer.chunk()` rejects non-positive `maxFrameSize`
- `CoalescedPacket._decodeVarInt()` and `HeaderProtection._readVarInt()` now guard against buffer over-read
- `PacketReceiver` discards all frames when any frame parse fails

### Removed
- 5 experimental `tmp_*.dart` crypto scratchpad files using deprecated `AESFastEngine`
- Unused imports and fields in `QuicConnection`

### Fixed
- Analyzer warnings: reduced from 10 to 0 in `lib/src/`

### Documentation
- Added 7 security audit reports (Blue Team V1/V2/V3, Red Team V1/V2/Novel, Meta-Analysis)
- Added `SECURITY_FIXES.md` tracking all 36 fixes
- Added `doc/POINTYCASTLE_4_MIGRATION.md`

---

## [0.1.0-alpha.1-pre] — 2026-06-25

### Added
- Initial alpha release with modular QUIC, HTTP/3, WebTransport, and libp2p components
- Wire format: VarInt, packet headers, frame types, coalesced packets
- Crypto: TLS 1.3 handshake scaffold, key derivation, header protection, packet protection
- Recovery: LossDetector, SentPacketTracker, CongestionController, RttEstimator, PtoScheduler
- Streams: StreamId, SendStateMachine, ReceiveStateMachine, ReassemblyBuffer, FlowController
- Connection: ConnectionStateMachine, ConnectionIdManager, ConnectionRegistry, MigrationHelper
- HTTP/3: All frame types, SETTINGS, QPACK static table encoder
- WebTransport: Session state machine, capsule types
- libp2p: Multiaddr parser, PeerId, DCUtR message scaffold
- 1000+ tests with 96%+ line coverage

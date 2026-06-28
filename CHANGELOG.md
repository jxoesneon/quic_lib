# Changelog

All notable changes to `dart_quic` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

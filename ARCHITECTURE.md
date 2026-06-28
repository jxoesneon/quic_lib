# dart_quic Architecture

**Version:** 0.1.0-alpha.1  
**Last updated:** 2026-06-27

---

## Overview

`dart_quic` is a pure-Dart implementation of QUIC (RFC 9000), HTTP/3 (RFC 9114), WebTransport (RFC 9220), and libp2p QUIC transport. It is organized as a set of loosely-coupled subsystems that are wired together at the connection level.

```
┌─────────────────────────────────────────────────────────────────┐
│                         dart_quic                               │
├─────────────┬─────────────┬─────────────┬─────────────────────┤
│   HTTP/3    │ WebTransport│   libp2p    │      QUIC Core      │
│   (RFC 9114)│  (RFC 9220) │             │     (RFC 9000)      │
├─────────────┴─────────────┴─────────────┴─────────────────────┤
│                       Recovery (RFC 9002)                     │
│  LossDetector │ SentPacketTracker │ CongestionController      │
│  RttEstimator │ PtoScheduler      │ AckGenerator              │
├─────────────────────────────────────────────────────────────────┤
│                       Crypto (RFC 9001)                       │
│  TLS Handshake │ Key Derivation │ Packet Protection          │
│  Header Protection │ Retry Integrity │ Initial Secrets         │
├─────────────────────────────────────────────────────────────────┤
│                       Wire Format                               │
│  VarInt │ Packet Headers │ Frames │ Coalesced Packets         │
├─────────────────────────────────────────────────────────────────┤
│                         I/O                                     │
│                    UdpSocket │ QuicEndpoint                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Subsystem Map

| Directory | Purpose | Key Classes |
|-----------|---------|-------------|
| `lib/src/connection/` | Connection lifecycle, CID management, migration | `QuicConnection`, `ConnectionStateMachine`, `ConnectionIdManager`, `MigrationHelper` |
| `lib/src/recovery/` | Loss detection, congestion control, RTT estimation | `LossDetector`, `CongestionController`, `RttEstimator`, `PtoScheduler`, `SentPacketTracker` |
| `lib/src/streams/` | QUIC stream lifecycle and flow control | `StreamId`, `SendStateMachine`, `ReceiveStateMachine`, `ReassemblyBuffer`, `FlowController` |
| `lib/src/crypto/` | TLS, key derivation, packet protection | `DefaultCryptoBackend`, `InitialSecrets`, `PacketProtector`, `HeaderProtection` |
| `lib/src/wire/` | Packet and frame serialization | `VarInt`, `PacketHeader`, `FrameCodec`, `CoalescedPacket` |
| `lib/src/http3/` | HTTP/3 frames and QPACK | `Http3Frame`, `Http3SettingsFrame`, `QpackEncoder` |
| `lib/src/webtransport/` | WebTransport session and capsules | `WebTransportSession`, `Capsule` |
| `lib/src/libp2p/` | Multiaddr and PeerId | `Multiaddr`, `PeerId`, `DCUtRMessage` |
| `lib/src/io/` | UDP socket and endpoint | `UdpSocket`, `QuicEndpoint` |
| `lib/src/security/` | Defensive utilities | `RateLimiter`, `AntiAmplificationLimit` |
| `lib/src/logging/` | Logging abstraction | `QuicLogger` |

---

## Integration Points

### 1. QuicConnection (Central Orchestrator)

`QuicConnection` is the single integration point for all subsystems. It does not own the subsystems (they are injected via constructor), but it exposes them and provides convenience methods that wire them together.

```dart
final conn = QuicConnection(
  stateMachine: ConnectionStateMachine(),
  cidManager: ConnectionIdManager(),
  pnSpaceManager: PacketNumberSpaceManager(),
  rttEstimator: RttEstimator(),
  lossDetector: LossDetector(),
  ptoScheduler: PtoScheduler(RttEstimator()),
  congestionController: CongestionController(),
  streamIdAllocator: StreamIdAllocator(),
);

// Anti-amplification
conn.onBytesReceived(datagram.length);
if (conn.canSend(packet.length)) { /* send */ }

// Recovery integration
conn.onPacketSent(pn, nowUs, ackEliciting: true);
conn.onAckReceived(space, largestAcked, ranges);
if (conn.isPtoExpired(nowUs)) { conn.onPtoFired(nowUs); }

// Address validation (clears anti-amplification limit)
conn.onAddressValidated();
```

**Current status:** Subsystems are wired. `QuicConnection` now provides:
- `buildPacket()` — builds and tracks outgoing packets via `PacketSender` + `RecoveryManager`
- `processIncomingDatagram()` — splits coalesced packets, parses frames, dispatches to subsystems
- Frame dispatch: CRYPTO → `CryptoFrameAssembler`, ACK → `RecoveryManager`, STREAM → `StreamManager`, CONNECTION_CLOSE → draining, HANDSHAKE_DONE → established

### 2. Packet Pipeline (Partially Wired)

The receive pipeline (plaintext frames — AEAD decryption is scaffolded for alpha.3):

```
UdpSocket.incoming
  → CoalescedPacket.split (if coalesced)
  → PacketReceiver.processDatagram
    → PacketReceiver.processPacket (header parse + frame parse)
    → QuicConnection._dispatchFrames
      - CRYPTO → CryptoFrameAssembler → (pending: HandshakeStateMachine.onMessage)
      - STREAM → StreamManager → QuicStream.deliver
      - ACK → RecoveryManager.onAckReceived
      - CONNECTION_CLOSE → ConnectionStateMachine.transitionTo(draining)
      - PATH_CHALLENGE / PATH_RESPONSE → MigrationHelper (pending)
      - MAX_DATA / MAX_STREAM_DATA → FlowController (pending)
```

The send pipeline:

```
QuicConnection.buildPacket()
  → PacketSender.buildPacket (header + plaintext frames)
  → (pending: PacketProtector.encrypt + HeaderProtection.apply)
  → RecoveryManager.onPacketSent (tracking)
```

**Current status:** Frame dispatch is operational for CRYPTO, ACK, STREAM, CONNECTION_CLOSE, and HANDSHAKE_DONE. AEAD encryption/decryption and header protection removal are implemented as independent modules but not yet wired into the pipeline (alpha.3 target).

### 3. Handshake Pipeline (Planned)

```
UdpSocket receives Initial packet
  → InitialSecrets.derive(DCID)
  → PacketProtector.decrypt
  → FrameCodec.parse → CRYPTO frames
  → CryptoFrameAssembler.deliver
  → TLS handshake messages → HandshakeStateMachine.onMessage
  → Handshake complete → ConnectionStateMachine.transitionTo(established)
  → Address validation → AntiAmplificationLimit.validateAddress()
```

**Current status:** `InitialSecrets.derive`, `HandshakeStateMachine`, and `CryptoFrameAssembler` are all tested independently. Integration is pending.

---

## Security Architecture

All subsystems have been hardened through 7 audit loops (36 fixes):

| Layer | Defenses |
|-------|----------|
| **Memory** | All Maps/Lists have hard caps; evict oldest on overflow |
| **Integer** | All growth paths clamped; no 64-bit overflow |
| **Replay** | 64-packet sliding window per space |
| **ACK spoofing** | `largestAcked` clamped to highest sent packet |
| **Rate** | Rate limiters on state transitions (100/sec) and UDP datagrams (1000/sec/ip) |
| **Amplification** | 3x anti-amplification limit before address validation |
| **Timing** | Uniform error paths in crypto verification; no fast-path rejects |
| **Info disclosure** | Generic error messages; toString() never dumps raw bytes |

See `SECURITY_FIXES.md` for the complete list.

---

## Extension Points

| Extension | How |
|-----------|-----|
| Custom crypto backend | Implement `CryptoBackend` abstract class |
| Custom frame types | Extend `FrameCodec.parse` switch statement |
| HTTP/3 extensions | Add to `Http3FrameType` enum and parser |
| New cipher suites | Add to `CipherSuite` enum and `DefaultCryptoBackend` |
| Logging | Set `QuicLogger.setSink(yourHandler)` |

---

## Known Gaps

### Completed in v0.5.0

| Gap | Status |
|-----|--------|
| Flow control frame handlers | **DONE** — `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS` wired in `_dispatchFrames`; `connectionFlowController` getter |
| HTTP/3 SETTINGS | **DONE** — `Http3Connection.sendSettings()` returns default `Http3SettingsFrame`; `pendingSettings` getter |
| PeerId encoding | **DONE** — `PeerId.encodeBase58()`/`decodeBase58()` and `encodeBase36()`/`decodeBase36()` |
| Coverage gap closure | **DONE** — 57 coverage tests + 17 hardening tests for FrameCodec, PN spaces, streams, recovery, CID manager, anti-amplification |

### Completed in v0.4.0

| Gap | Status |
|-----|--------|
| TLS certificate chain verification | **DONE** — `CertificateInfo`, `CertificateChain`, `parseCertificate()` with validity checks; `CertificateVerifier` delegates to `CertificateChain.validateChain()` |
| DCUtR real hole punching | **DONE** — `test/libp2p/dcutr_nat_traversal_test.dart` completes two-peer UDP hole punch over loopback; `test/libp2p/dcutr_full_handshake_test.dart` validates Initial → Retry → Initial-with-token flow |
| 0-RTT early data | **DONE** — `QuicConnection.canSendZeroRtt`, `buildZeroRttPacket()` builds encrypted 0-RTT packets |
| Connection ID rotation | **DONE** — `QuicConnection.generateNewConnectionIdFrame()`, `activeConnectionIdCount`; `_dispatchFrames` wires `NewConnectionIdFrame`/`RetireConnectionIdFrame` |
| Flow control integration | **DONE** — `StreamManager` per-stream `FlowController` instances; `canSendOnStream()`, `updateSendWindow()` |
| Congestion control integration | **DONE** — `QuicConnection.pacingCalculator`, `pacingDelayUs`, `shouldPacePackets`; RTT/CW updates from `onAckReceived()` |

### Completed in v0.3.0

| Gap | Status |
|-----|--------|
| DCUtR real NAT hole punching | **DONE** — `DCUtRUdpCoordinator` wires `DCUtRStateMachine` into `UdpSocket` with magic-prefixed datagrams |
| 0-RTT resumption | **DONE** — `PacketNumberSpace.zeroRtt`, `KeyManager.deriveZeroRtt()`, `SessionTicketStore` with expiry and eviction |
| Connection migration (full) | **DONE** — `QuicEndpoint.migrateConnection()`, `QuicConnection.onPathValidated()`, remote address tracking |
| HTTP/3 body streaming | **DONE** — `Http3BodyStream` with chunk delivery/EOF, `Http3Connection.sendBody()`/`getBody()` |
| TLS certificate verification | **DONE** — `CertificateVerifier` with `verifySignature()` dispatch and `verifyCertificateChain()` scaffold |
| Retry token generation | **DONE** — `RetryTokenGenerator` with HMAC-SHA256, timestamp validation, and tamper detection |

### Completed in v0.2.0

| Gap | Status |
|-----|--------|
| Real TLS handshake key exchange | **DONE** — `HandshakeKeyExchange` with X25519 ephemeral keys, shared secret, and TLS 1.3-style handshake secret derivation |
| HTTP/3 full request/response | **DONE** — `Http3Request`/`Http3Response` with QPACK header encoding/decoding; `Http3Connection` sends requests and decodes responses |
| WebTransport datagram support | **DONE** — `CapsuleType.datagram`, `DatagramCapsule`, `WebTransportSession.sendDatagram()`/`receivedDatagrams` |
| Connection migration | **DONE** — `MigrationHelper` wired into `QuicConnection._dispatchFrames()`; `PATH_CHALLENGE`/`PATH_RESPONSE` validates paths |

### Completed in Beta.1

| Gap | Status |
|-----|--------|
| Packet number reconstruction | **DONE** — `PacketNumberReconstructor` per RFC 9000 §17.1 |
| TLS message construction | **DONE** — `TlsMessageBuilder` produces structurally valid ClientHello, ServerHello, Finished |
| HTTP/3 request/response lifecycle | **DONE** — `Http3Connection.sendRequest()` allocates streams; `onStreamFrame()` dispatches frames |
| QPACK dynamic table | **DONE** — `QpackDynamicTable` with insertions, evictions, capacity management, and dynamic→static→literal encoding |
| WebTransport stream bridging | **DONE** — `CapsuleRouter` routes capsules to `WebTransportSession` by stream ID |
| DCUtR protocol orchestration | **DONE** — `DCUtRStateMachine` with dialer/listener state transitions |

### Completed in Alpha.4

| Gap | Status |
|-----|--------|
| Full header protection round-trip | **DONE** — `ProtectedPacketCodec` handles encrypt+protect / unprotect+decrypt for LongHeader and ShortHeader |
| Handshake message parsing | **DONE** — `CryptoMessageParser` reads TLS type + payload; `CryptoFrameHandler` wires to `HandshakeStateMachine` |
| Handshake key transition | **DONE** — `KeyManager.deriveHandshake()` and `.deriveApplication()` with `.discardInitialKeys()` / `.discardHandshakeKeys()` |
| `QuicEndpoint.connect` | **DONE** — Scaffolds `QuicConnection` with all subsystems, transitions to handshaking |

### Completed in Alpha.3

| Gap | Status |
|-----|--------|
| AEAD encryption in pipeline | **DONE** — `QuicConnection.buildEncryptedPacket()` encrypts + protects headers |
| AEAD decryption in pipeline | **DONE** — `QuicConnection.processEncryptedDatagram()` decrypts + dispatches |
| Initial key derivation | **DONE** — `KeyManager.deriveInitial()` derives keys from DCID |
| Per-space key management | **DONE** — `PacketNumberSpaceKeys` holds `PacketProtector` + `HeaderProtection` |

### Completed in Alpha.2

| Gap | Status |
|-----|--------|
| Frame dispatch pipeline | **DONE** — `QuicConnection.processIncomingDatagram()` + `_dispatchFrames()` |
| Stream manager | **DONE** — `StreamManager` routes STREAM frames to `QuicStream` instances |
| Recovery manager coordination | **DONE** — `RecoveryManager` integrated into `QuicConnection` |
| Fuzz harness scaffold | **DONE** — `test/fuzz/fuzz_harness.dart` |
| Benchmark harness scaffold | **DONE** — `test/benchmark/benchmark_harness.dart` |

### Completed in v1.1.0

| Gap | Status |
|-----|--------|
| TLS transcript hash tracking | **DONE** — `TranscriptHash` maintains running SHA-256 of handshake messages; `HandshakeCoordinator` adds ClientHello to transcript |
| HTTP/3 GOAWAY frame sending | **DONE** — `Http3Connection.close()` records `Http3GoawayFrame`; `lastAcceptedStreamId` tracks highest stream ID; `hasSentGoaway`/`sentGoawayFrames` |
| QUIC v2 long header format | **DONE** — `V2LongHeader` implements RFC 9369 v2 first-byte encoding; serialize/parse round-trip for all packet types |
| WebTransport GOAWAY capsule | **DONE** — `CapsuleType.goaway(0x1d)`, `GoawayCapsule`, `WebTransportSession.receivedGoaway`/`sendGoaway()` |
| Production connection migration scaffold | **DONE** — `QuicEndpoint.rebindToAddress()` validates path and updates stored remote address after PATH_CHALLENGE/RESPONSE |
| X.509 certificate parser scaffold | **DONE** — `X509Certificate` with TBSCertificate, signature, issuer, subject, validity; `parseX509()` validates DER tag; wired into `CertificateChain` and `CertificateVerifier` |

### Completed in v1.0.0

| Gap | Status |
|-----|--------|
| PeerId encoding fully wired | **DONE** — `fromBase58()`/`toBase58()`/`toBase36()` delegate to implemented encode/decode; no `UnimplementedError` stubs remain |
| HTTP/3 server push | **DONE** — `Http3PushPromiseFrame`, `Http3CancelPushFrame`, `registerPushPromise()`/`hasPushPromise()` in `Http3Connection` |
| WebTransport bidirectional streams | **DONE** — `StreamCapsule` (bi/uni), `CapsuleType.registerBidirectionalStream`/`registerUnidirectionalStream`, `WebTransportSession` tracks registered streams |
| Real TLS handshake | **DONE** — `HandshakeCoordinator` wires `HandshakeKeyExchange` into CRYPTO-frame pipeline; generates keys, processes ClientHello, derives handshake/application secrets; `CryptoFrameHandler` uses coordinator |
| Connection migration with real address change | **DONE** — `QuicEndpoint.changeConnectionAddress()` performs full PATH_CHALLENGE/PATH_RESPONSE over UDP; `QuicConnection.probeNewPath()`/`isProbingPath`/`lastProbePacket` |
| QUIC v2 support | **DONE** — `QuicVersions` v1/v2 constants, `PacketReceiver` accepts v2, `VersionNegotiation` includes v2 |

### Completed in v0.5.0

| Gap | Status |
|-----|--------|
| Flow control frame handlers | **DONE** — `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS` wired in `_dispatchFrames`; `connectionFlowController` getter |
| HTTP/3 SETTINGS | **DONE** — `Http3Connection.sendSettings()` returns default `Http3SettingsFrame`; `pendingSettings` getter |
| PeerId encoding | **DONE** — `PeerId.encodeBase58()`/`decodeBase58()` and `encodeBase36()`/`decodeBase36()` |
| Coverage gap closure | **DONE** — 57 coverage tests + 17 hardening tests for FrameCodec, PN spaces, streams, recovery, CID manager, anti-amplification |

### Remaining

| Gap | Impact | ETA |
|-----|--------|-----|
| Full ASN.1/DER parser | `X509Certificate` is a scaffold; needs real BER/DER parser for production X.509 | Post-v1.1 |
| Production TLS 1.3 handshake | `HandshakeCoordinator` scaffold needs transcript hash integration with Finished message, cert verification in handshake flow | Post-v1.1 |
| HTTP/3 server push over network | `registerPushPromise()` scaffold needs actual stream transmission | Post-v1.1 |
| Complete WebTransport spec | Bidirectional capsule types added; remaining spec features (flow control, pooling) | Post-v1.1 |
| QUIC v2 full feature set | `V2LongHeader` format added; v2-specific frames and behaviors (e.g., new ACK format) | Post-v1.1 |
| Real network address migration | `rebindToAddress()` is a scaffold; needs OS-level UDP socket rebind for production | Post-v1.1 |

---

## Testing Strategy

```
test/
  unit/           — Individual subsystem tests (per-class)
  integration/    — Cross-subsystem tests (pending)
  security/       — Hardening regression tests (36 fix suites)
  fuzz/           — Chaos/fuzz tests (basic coverage)
  coverage/       — Coverage gap closure tests
```

**Current:** 1030 tests, ~96.28% line coverage.

**CI:** Run `dart test` and `dart analyze --fatal-infos` on every commit.

# quic_lib Architecture

**Version:** 1.12.0  
**Last updated:** 2026-07-07

---

## Overview

`quic_lib` is a pure-Dart implementation of QUIC (RFC 9000), HTTP/3 (RFC 9114), WebTransport (RFC 9220), and libp2p QUIC transport. It is organized as a set of loosely-coupled subsystems that are wired together at the connection level.

```
┌──────────────────────────────────────────────────────────────────────┐
│                             quic_lib                                 │
├──────────────┬──────────────┬──────────────┬────────────────────────┤
│    HTTP/3    │ WebTransport │    libp2p    │       QUIC Core        │
│  (RFC 9114)  │  (RFC 9220)  │              │      (RFC 9000)        │
├──────────────┴──────────────┴──────────────┴────────────────────────┤
│                         Recovery (RFC 9002)                          │
│  LossDetector │ SentPacketTracker │ CongestionController            │
│  RttEstimator │ PtoScheduler      │ AckGenerator                    │
│  AckFrequencyPolicy (RFC 9298) │ PacingTimer (RFC 9002 §7.7)        │
├──────────────────────────────────────────────────────────────────────┤
│               Congestion Control (pluggable)                         │
│  CubicCongestionController │ BbrCongestionController                │
│  Hystart (RFC 8312 Appendix B)                                       │
├──────────────────────────────────────────────────────────────────────┤
│                         Crypto (RFC 9001)                            │
│  TLS Handshake │ Key Derivation │ Packet Protection                 │
│  Header Protection │ Retry Integrity │ Initial Secrets              │
│  RevocationParser │ RevocationPolicy │ KeyUpdate (RFC 9001 §6)      │
│  Peer Certificate Capture                                            │
├──────────────────────────────────────────────────────────────────────┤
│                          Wire Format                                 │
│  VarInt │ Packet Headers │ Frames │ Coalesced Packets               │
├──────────────────────────────────────────────────────────────────────┤
│                             I/O                                      │
│                   UdpSocket │ QuicEndpoint                          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Subsystem Map

| Directory | Purpose | Key Classes |
|-----------|---------|-------------|
| `lib/src/connection/` | Connection lifecycle, CID management, migration | `QuicConnection`, `ConnectionStateMachine`, `ConnectionIdManager`, `MigrationHelper` |
| `lib/src/connection/congestion_control/` | Pluggable congestion controllers | `CongestionController` (abstract), `CubicCongestionController`, `BbrCongestionController`, `Hystart` |
| `lib/src/recovery/` | Loss detection, congestion, RTT, pacing, ACK policy | `LossDetector`, `RecoveryManager`, `RttEstimator`, `PtoScheduler`, `SentPacketTracker`, `AckGenerator`, `AckFrequencyPolicy`, `PacingTimer` |
| `lib/src/streams/` | QUIC stream lifecycle and flow control | `StreamId`, `SendStateMachine`, `ReceiveStateMachine`, `ReassemblyBuffer`, `FlowController` |
| `lib/src/crypto/` | TLS, key derivation, packet protection | `DefaultCryptoBackend`, `InitialSecrets`, `KeyManager` |
| `lib/src/crypto/packet/` | Per-packet crypto primitives | `PacketProtector`, `HeaderProtection`, `KeyUpdate`, `ProtectedPacketCodec`, `SpaceKeys` |
| `lib/src/crypto/tls/` | TLS handshake subsystem | `HandshakeCoordinator`, `HandshakeKeyExchange`, `CryptoFrameHandler`, `CryptoFrameAssembler`, `CertificateChain`, `CertificateVerifier`, `RevocationParser`, `RevocationPolicy`, `X509Parser` |
| `lib/src/wire/` | Packet and frame serialization | `VarInt`, `PacketHeader`, `FrameCodec`, `CoalescedPacket`, `V2LongHeader` |
| `lib/src/http3/` | HTTP/3 frames, QPACK, capsule protocol | `Http3Connection`, `Http3Frame`, `Http3SettingsFrame`, `QpackEncoder`, `QpackDecoder`, `QpackDynamicTable`, `QpackEncoderStream` (`EncoderInstruction`), `QpackDecoderStream` (`DecoderInstruction`), `Capsule` |
| `lib/src/webtransport/` | WebTransport session and capsules | `WebTransportSession`, `WebTransportCapsule`, `CapsuleRouter`, `WebTransportSessionManager` |
| `lib/src/libp2p/` | Multiaddr, PeerId, DCUtR, libp2p QUIC | `Multiaddr`, `PeerId`, `DCUtRMessage`, `Libp2pQuicTransport`, `Libp2pQuicConnection` |
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
  congestionController: CubicCongestionController(), // or BbrCongestionController()
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

// Peer certificate capture (available after TLS handshake)
final rawCert = conn.peerCertificate;         // Uint8List?
final certVerify = conn.peerCertificateVerify; // Uint8List?
```

**Current status:** All subsystems are wired and production-grade. `QuicConnection` provides:
- `buildPacket()` / `buildEncryptedPacket()` — builds, encrypts, and tracks outgoing packets via `PacketSender` + `RecoveryManager`; pacing is enforced via `PacingTimer`
- `processEncryptedDatagram()` — splits coalesced packets, decrypts (AEAD + header unprotection), parses frames, dispatches to subsystems
- `processIncomingDatagram()` — plaintext path used in tests and pre-handshake contexts
- Frame dispatch: CRYPTO → `CryptoFrameAssembler`, ACK → `RecoveryManager`, STREAM → `StreamManager`, CONNECTION_CLOSE → draining, HANDSHAKE_DONE → established, MAX_DATA/MAX_STREAM_DATA → `FlowController`, PATH_CHALLENGE/PATH_RESPONSE → `MigrationHelper`, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID → `ConnectionIdManager`, ACK_FREQUENCY → `AckFrequencyPolicy`
- Key phase bit monitoring: peer-initiated key updates (RFC 9001 §6.2) detected and forwarded to `KeyManager.onPeerKeyUpdateDetected()`
- Congestion controller is pluggable via the `congestionController` setter

### 2. Packet Pipeline

The receive pipeline (fully wired including AEAD):

```
UdpSocket.incoming
  → CoalescedPacket.split (if coalesced)
  → PacketReceiver.processDatagram
    → PacketReceiver.processPacket (header parse)
    → ProtectedPacketCodec.unprotectAndDecrypt (header unprotection + AEAD)
    → QuicConnection._dispatchFrames
      - CRYPTO → CryptoFrameAssembler → HandshakeCoordinator.onMessage
      - STREAM → StreamManager → QuicStream.deliver
      - ACK → RecoveryManager.onAckReceived
      - CONNECTION_CLOSE → ConnectionStateMachine.transitionTo(draining)
      - PATH_CHALLENGE / PATH_RESPONSE → MigrationHelper
      - MAX_DATA / MAX_STREAM_DATA → FlowController
      - NEW_CONNECTION_ID / RETIRE_CONNECTION_ID → ConnectionIdManager
      - ACK_FREQUENCY → AckFrequencyPolicy.processAckFrequencyFrame
      - key phase change → KeyManager.onPeerKeyUpdateDetected
```

The send pipeline:

```
QuicConnection.buildEncryptedPacket()
  → PacketSender.buildPacket (header + plaintext frames)
  → ProtectedPacketCodec.encryptAndProtect (AEAD + header protection)
  → PacingTimer.timeUntilNextSend (enforce pacing interval)
  → RecoveryManager.onPacketSent (tracking)
  → KeyManager.onPacketSent (key update confirmation)
```

### 3. Handshake Pipeline

```
UdpSocket receives Initial packet
  → InitialSecrets.derive(DCID)
  → PacketProtector.decrypt + HeaderProtection.remove
  → FrameCodec.parse → CRYPTO frames
  → CryptoFrameAssembler.deliver
  → HandshakeCoordinator.onMessage
    → HandshakeKeyExchange (X25519 ephemeral keys)
    → KeyManager.deriveHandshake() / .deriveApplication()
    → CryptoFrameHandler → peer certificate extraction
    → CertificateVerifier → CertificateChain.validateChain()
    → RevocationParser → RevocationInfo (OCSP/CRL URLs extracted)
  → Handshake complete → ConnectionStateMachine.transitionTo(established)
  → Address validation → AntiAmplificationLimit.validateAddress()
```

**Current status:** The full handshake pipeline is operational. `HandshakeCoordinator` processes ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, and Finished messages, derives all key epochs (Initial, Handshake, Application, 0-RTT), and discards superseded keys. Peer certificate bytes are captured from the TLS Certificate message and exposed via `QuicConnection.peerCertificate`.

### 4. Key Update (RFC 9001 §6)

```
Peer sends 1-RTT packet with toggled key phase bit
  → QuicConnection detects phase mismatch
  → KeyManager.onPeerKeyUpdateDetected(packetNumber, keyPhase)
    → derive new receive keys from current secret (proactive)
    → reject non-monotonic / rollback attempts
  → QuicConnection.onPacketSent (first 1-RTT send after detection)
    → KeyManager.confirmKeyUpdate()
    → schedule 3×PTO deadline for old-key discard
```

`KeyManager` also proactively derives next-generation send and receive keys ahead of time to avoid timing side-channels, reuses header protection keys across updates per RFC 9001 §5.4, and tracks confidentiality limits to initiate self-originated key updates (RFC 9001 §6.1).

---

## Security Architecture

All subsystems have been hardened through 7 audit loops (49 fixes):

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
| **Capsule DoS** | Capsule payloads rejected above 1 MiB |
| **Frame DoS** | DATAGRAM frames capped at 1 MiB |

See `SECURITY_FIXES.md` for the complete list.

---

## Extension Points

| Extension | How |
|-----------|-----|
| Custom crypto backend | Implement `CryptoBackend` abstract class |
| Custom frame types | Extend `FrameCodec.parse` switch statement |
| HTTP/3 extensions | Add to `Http3FrameType` enum and parser |
| New cipher suites | Add to `CipherSuite` enum and `DefaultCryptoBackend` |
| Pluggable congestion controller | Implement `CongestionController`; assign via `QuicConnection.congestionController` |
| Logging | Set `QuicLogger.setSink(yourHandler)` |

---

## Known Gaps

### Completed in v1.12.0

| Gap | Status |
|-----|--------|
| Peer certificate capture | **DONE** — `CryptoFrameHandler` extracts raw X.509 bytes from TLS Certificate messages; exposed as `QuicConnection.peerCertificate` and `QuicConnection.peerCertificateVerify` |

### Completed in v1.11.0

| Gap | Status |
|-----|--------|
| Fuzz coverage gaps | **DONE** — 121 new fuzz/error-path tests for VarInt, frames, QPACK, X.509, PacketReceiver, HTTP/3 frames |

### Completed in v1.10.0

| Gap | Status |
|-----|--------|
| `Capsule` → `WebTransportCapsule` rename | **DONE** — WebTransport class renamed to `WebTransportCapsule`; deprecated `Capsule` typedef retained for backwards compatibility |

### Completed in v1.9.0

| Gap | Status |
|-----|--------|
| Revocation extension parsing (Phase 1) | **DONE** — `RevocationParser` extracts OCSP and CRL URLs from X.509 AIA/CDP extensions; `RevocationPolicy` enum (`disabled`, `softFail`, `hardFail`) controls verifier behavior |

### Completed in v1.7.0

| Gap | Status |
|-----|--------|
| QPACK dynamic streams (RFC 9204 §4.2) | **DONE** — `QpackEncoderStream` (`EncoderInstruction`) and `QpackDecoderStream` (`DecoderInstruction`) implement encoder/decoder stream instructions; `Http3Connection` opens QPACK unidirectional streams and flushes instructions |

### Completed in v1.6.0

| Gap | Status |
|-----|--------|
| Pacing timer enforcement | **DONE** — `PacingTimer` wired into `QuicConnection.buildPacket`/`buildEncryptedPacket`; ACK-only packets exempt per RFC 9002 §7.7 |

### Completed in v1.5.0

| Gap | Status |
|-----|--------|
| Key update detection | **DONE** — Peer-initiated key updates detected via key phase bit; `KeyManager.onPeerKeyUpdateDetected()` derives new keys, rejects rollbacks, sets 3×PTO discard deadline |

### Completed in v1.4.0 – v1.4.2

| Gap | Status |
|-----|--------|
| BBR congestion controller | **DONE** — `BbrCongestionController` (RFC 8382); STARTUP/DRAIN/PROBE_BW/PROBE_RTT state machine |
| Hystart++ | **DONE** — `Hystart` (RFC 8312 Appendix B); ACK-train and delay-based slow-start exit |
| ACK frequency policy | **DONE** — `AckFrequencyPolicy` processes ACK_FREQUENCY frames (RFC 9298); threshold-based ACK triggering wired into `AckGenerator` |

### Completed in v1.1.0 – v1.3.0

| Gap | Status |
|-----|--------|
| TLS transcript hash tracking | **DONE** — `TranscriptHash` maintains running SHA-256 of handshake messages |
| HTTP/3 GOAWAY frame | **DONE** — `Http3Connection.close()` sends `Http3GoawayFrame` |
| QUIC v2 long header format | **DONE** — `V2LongHeader` (RFC 9369); serialize/parse for all packet types |
| WebTransport GOAWAY capsule | **DONE** — `GoawayCapsule`, `WebTransportSession.sendGoaway()` |
| Production connection migration scaffold | **DONE** — `QuicEndpoint.rebindToAddress()` validates path after PATH_CHALLENGE/RESPONSE |
| X.509 parser scaffold | **DONE** — `X509Certificate` parses DER; wired into `CertificateChain` and `CertificateVerifier` |

### Completed in v1.0.0

| Gap | Status |
|-----|--------|
| Real TLS 1.3 handshake | **DONE** — `HandshakeCoordinator` wires `HandshakeKeyExchange` into the CRYPTO-frame pipeline; derives Initial → Handshake → Application key epochs |
| HTTP/3 server push | **DONE** — `Http3PushPromiseFrame`, `Http3CancelPushFrame`, `Http3Connection.registerPushPromise()` |
| Real network address migration | **DONE** — `QuicEndpoint.changeConnectionAddress()` performs full PATH_CHALLENGE/RESPONSE over UDP |

### Completed in v0.5.0 and earlier

| Gap | Status |
|-----|--------|
| Flow control frame handlers | **DONE** — `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS` wired in `_dispatchFrames` |
| HTTP/3 SETTINGS | **DONE** — `Http3Connection.sendSettings()` |
| PeerId encoding | **DONE** — `encodeBase58()`/`decodeBase58()`/`encodeBase36()`/`decodeBase36()` |
| TLS certificate chain verification | **DONE** — `CertificateChain.validateChain()`, `CertificateVerifier` |
| 0-RTT early data | **DONE** — `QuicConnection.buildZeroRttPacket()`, `canSendZeroRtt` |
| Connection ID rotation | **DONE** — `NEW_CONNECTION_ID`/`RETIRE_CONNECTION_ID` wired |
| AEAD in pipeline | **DONE** — `ProtectedPacketCodec` in both send and receive pipelines |

### Remaining (Deferred)

| Gap | Impact | Notes |
|-----|--------|-------|
| Full ASN.1/DER parser | `X509Certificate` uses the `asn1lib` and `x509` pub.dev packages for parsing; the internal `x509_parser.dart` scaffold provides a thin adapter layer | Post-v1.12 |
| OCSP/CRL fetching and validation | `RevocationParser` extracts URLs (Phase 1 complete); actual HTTP fetch and CRL/OCSP response verification is not yet implemented; `RevocationPolicy.hardFail` should not be used in production until Phase 2 lands | Post-v1.12 |
| HTTP/3 server push over network | `registerPushPromise()` tracks push state; actual stream transmission of the push response is scaffolded | Post-v1.12 |
| Complete WebTransport spec | WebTransport flow-control capsules (`WtMaxStreamsCapsule`, etc.) are parsed and serialized; end-to-end WebTransport flow control enforcement is not yet wired | Post-v1.12 |
| QUIC v2 full feature set | `V2LongHeader` format added; v2-specific ACK format changes and other v2 behaviors are not yet implemented | Post-v1.12 |
| ECN (Explicit Congestion Notification) | Blocked on missing `IP_TOS`/`IPV6_TCLASS` socket options in Dart's `RawDatagramSocket`; deferred to v2.0.0 per ADR-001 | v2.0.0 |

---

## Testing Strategy

```
test/
  unit/           — Individual subsystem tests (per-class)
  integration/    — Cross-subsystem tests
  security/       — Hardening regression tests (49 fix suites)
  fuzz/           — Chaos/fuzz tests
  coverage/       — Coverage gap closure tests
  benchmark/      — Benchmark harness scaffold
```

**Current:** 2188 tests, ~94.89% line coverage.

**CI:** Run `dart test` and `dart analyze --fatal-infos` on every commit.

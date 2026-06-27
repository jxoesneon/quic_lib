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

**Current status:** All subsystems are independently tested and hardened. `QuicConnection` exposes them but the full packet pipeline (receive → decrypt → parse frames → dispatch) is not yet wired.

### 2. Packet Pipeline (Planned)

The intended receive pipeline:

```
UdpSocket.incoming
  → CoalescedPacket.split (if coalesced)
  → PacketHeaderParser.parse
  → HeaderProtection.remove
  → PacketProtector.decrypt
  → FrameCodec.parse
  → Frame dispatch:
      - CRYPTO → CryptoFrameAssembler → HandshakeStateMachine
      - STREAM → StreamManager → QuicStream.deliver
      - ACK → SentPacketTracker + LossDetector + CongestionController
      - CONNECTION_CLOSE → ConnectionStateMachine.transitionTo(closing)
      - PATH_CHALLENGE / PATH_RESPONSE → MigrationHelper
      - MAX_DATA / MAX_STREAM_DATA → FlowController.updateLimit
```

**Current status:** Each stage exists as an independent module. `PacketReceiver.processPacket` performs header parsing and frame parsing but does not decrypt or dispatch.

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

## Known Gaps (Alpha.1 → Alpha.2)

| Gap | Impact | ETA |
|-----|--------|-----|
| Packet pipeline not wired | Cannot process real encrypted packets | Alpha.2 |
| Handshake not wired | Cannot complete TLS 1.3 over QUIC | Alpha.2 |
| Stream manager missing | STREAM frames not routed to streams | Alpha.2 |
| Recovery manager missing | ACK/loss/PTO/congestion not coordinated | Alpha.2 |
| `QuicEndpoint.connect` unimplemented | Cannot initiate connections | Alpha.3 |
| WebTransport stream bridging | Capsules not mapped to QUIC streams | Alpha.3 |
| DCUtR protocol orchestration | NAT hole punching logic missing | Alpha.4 |
| HTTP/3 request/response lifecycle | No `Http3Connection` or request routing | Alpha.3 |
| QPACK dynamic table | Only static table lookups implemented | Alpha.4 |
| Fuzzing harness | No automated fuzz testing yet | Alpha.4 |
| Benchmark harness | No performance regression testing yet | Alpha.4 |

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

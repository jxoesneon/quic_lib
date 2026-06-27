# Module Overview

**Version**: 1.0-draft  
**Status**: Architecture  
**Subsystem**: System Design

---

## 1. Purpose

This document describes the modular architecture of `dart_quic`: the layering of subsystems, their responsibilities, boundaries, and inter-module communication contracts.

---

## 2. Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Adapters                       │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │  HTTP/3  │  │ WebTransport │  │   libp2p Adapter      │ │
│  └────┬─────┘  └──────┬───────┘  └───────────┬───────────┘ │
├───────┼────────────────┼──────────────────────┼─────────────┤
│       └────────────────┼──────────────────────┘             │
│                        │                                     │
│  ┌─────────────────────┴─────────────────────────────────┐  │
│  │              Stream Manager                            │  │
│  │  (multiplexing, flow control, reassembly, scheduling) │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                           │                                  │
│  ┌────────────────────────┴──────────────────────────────┐  │
│  │           Connection Manager                           │  │
│  │  (state machine, migration, idle timeout, CID mgmt)   │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                           │                                  │
│  ┌───────────┐  ┌────────┴────────┐  ┌──────────────────┐  │
│  │  Recovery │  │  Packet Engine  │  │   TLS Engine     │  │
│  │  (loss,   │  │  (encrypt,      │  │   (handshake,    │  │
│  │  CC, PTO) │  │  decrypt, HP)   │  │   key schedule)  │  │
│  └─────┬─────┘  └────────┬────────┘  └────────┬─────────┘  │
│        └─────────────────┬┘                    │            │
│                          │                     │            │
│  ┌───────────────────────┴─────────────────────┴─────────┐  │
│  │                 Wire Codec                             │  │
│  │  (varint, headers, frames, packet number encoding)    │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                           │                                  │
│  ┌────────────────────────┴──────────────────────────────┐  │
│  │                  UDP I/O                               │  │
│  │  (RawDatagramSocket, send/recv, batching)             │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Module Catalog

### 3.1 UDP I/O (`src/io/`)

**Responsibility**: Raw UDP datagram send/receive.

| Component | Role |
|-----------|------|
| `UdpSocket` | Wraps `RawDatagramSocket`; async event loop integration |
| `DatagramBatch` | Groups multiple datagrams for efficiency |
| `AddressManager` | Tracks local/remote addresses for migration |

**Interfaces**:
- IN: Raw bytes from network
- OUT: Raw bytes to network
- UP: Parsed datagrams to Packet Engine

### 3.2 Wire Codec (`src/wire/`)

**Responsibility**: Encode/decode all QUIC wire formats.

| Component | Role |
|-----------|------|
| `VarInt` | Variable-length integer codec |
| `PacketParser` | Long/short header parsing |
| `PacketBuilder` | Packet construction |
| `FrameCodec` | All 20+ frame types |
| `PacketNumber` | Encoding/decoding/reconstruction |

**Interfaces**:
- IN: Raw bytes
- OUT: Structured `Packet` / `Frame` objects
- No external dependencies

### 3.3 TLS Engine (`src/crypto/tls/`)

**Responsibility**: TLS 1.3 handshake, key schedule, certificate management.

| Component | Role |
|-----------|------|
| `TlsEngine` | Handshake state machine |
| `KeySchedule` | HKDF-based key derivation |
| `CertificateManager` | Certificate loading, validation |
| `TransportParams` | Serialize/deserialize QUIC transport parameters |

**Interfaces**:
- IN: Handshake bytes from CRYPTO frames
- OUT: Handshake bytes to send; traffic secrets
- UP: Secrets provided to Packet Engine

### 3.4 Packet Engine (`src/crypto/packet/`)

**Responsibility**: AEAD encryption/decryption, header protection.

| Component | Role |
|-----------|------|
| `PacketProtector` | AEAD encrypt/decrypt per encryption level |
| `HeaderProtection` | Apply/remove header protection |
| `NonceGenerator` | Construct nonce from IV + packet number |
| `KeyManager` | Track current/next keys; handle key updates |

**Interfaces**:
- IN: Plaintext packets (from Wire Codec) + secrets (from TLS)
- OUT: Protected packets (to UDP I/O) / Decrypted packets (to Stream Manager)

### 3.5 Recovery (`src/recovery/`)

**Responsibility**: Loss detection, congestion control, RTT estimation.

| Component | Role |
|-----------|------|
| `RttEstimator` | Smoothed RTT, rttvar, min_rtt |
| `LossDetector` | Packet/time threshold detection; PTO |
| `CongestionController` | Interface + NewReno/CUBIC implementations |
| `Pacer` | Token-bucket pacing |
| `SentPacketTracker` | Per-space sent packet metadata |

**Interfaces**:
- IN: ACK frames, sent packet info, timer events
- OUT: Loss events, send permission, pacing delay
- UP: Retransmission requests to Stream Manager

### 3.6 Connection Manager (`src/connection/`)

**Responsibility**: Connection lifecycle, state machine, CID management.

| Component | Role |
|-----------|------|
| `ConnectionStateMachine` | Handshaking → Established → Closing → Closed |
| `ConnectionIdManager` | Issue, rotate, retire CIDs |
| `MigrationHandler` | PATH_CHALLENGE/RESPONSE, address validation |
| `IdleTimer` | Close connection on timeout |
| `VersionNegotiator` | Handle version negotiation packets |

**Interfaces**:
- IN: Events from all lower modules
- OUT: Connection-level decisions (close, migrate, negotiate)
- UP: Connection state to application layer

### 3.7 Stream Manager (`src/streams/`)

**Responsibility**: Stream multiplexing, flow control, data delivery.

| Component | Role |
|-----------|------|
| `StreamRegistry` | Track all open streams by ID |
| `FlowController` | Connection-level and stream-level flow control |
| `ReassemblyBuffer` | Per-stream ordered byte reassembly |
| `StreamScheduler` | Decide which stream to send data from |
| `SendBuffer` | Per-stream outgoing data buffer |

**Interfaces**:
- IN: STREAM frames (from decrypted packets); flow control frames
- OUT: STREAM frames (for encryption); flow control frames
- UP: Ordered byte streams to application adapters

### 3.8 HTTP/3 (`src/http3/`)

**Responsibility**: HTTP/3 protocol layer.

| Component | Role |
|-----------|------|
| `Http3Connection` | Manages control/QPACK streams |
| `QpackEncoder` | Encode HTTP fields |
| `QpackDecoder` | Decode HTTP fields |
| `Http3FrameCodec` | HTTP/3 frame types |
| `RequestHandler` | Client request/response logic |
| `ServerHandler` | Server request/response logic |

### 3.9 WebTransport (`src/webtransport/`)

**Responsibility**: WebTransport session management.

| Component | Role |
|-----------|------|
| `SessionManager` | Track active sessions |
| `StreamRouter` | Route streams by session ID |
| `DatagramRouter` | Route datagrams by quarter stream ID |
| `CapsuleHandler` | CLOSE/DRAIN lifecycle |

### 3.10 libp2p Adapter (`src/libp2p/`)

**Responsibility**: libp2p-specific QUIC integration.

| Component | Role |
|-----------|------|
| `MultiaddrParser` | Parse /udp/.../quic-v1 |
| `Libp2pCertGenerator` | Generate certs with extension |
| `PeerIdDeriver` | Extract and validate Peer IDs |
| `MultistreamSelect` | Protocol negotiation on streams |

---

## 4. Module Boundaries

### 4.1 Dependency Rules

1. **Downward only**: Higher layers depend on lower layers, never the reverse.
2. **No lateral**: Modules at the same layer do not directly depend on each other (communicate via the layer below or events).
3. **Interface-based**: All inter-module communication uses abstract interfaces.
4. **No circular**: Dependency graph is a DAG.

### 4.2 Dependency Matrix

| Module | Depends On |
|--------|-----------|
| UDP I/O | dart:io |
| Wire Codec | (none) |
| TLS Engine | Wire Codec (for transport params), Crypto backend |
| Packet Engine | Wire Codec, TLS Engine (for secrets), Crypto backend |
| Recovery | Wire Codec (ACK frames), Timer |
| Connection Manager | All core modules |
| Stream Manager | Wire Codec, Recovery |
| HTTP/3 | Stream Manager, Wire Codec |
| WebTransport | HTTP/3, Stream Manager |
| libp2p | Stream Manager, TLS Engine |

---

## 5. Concurrency Model

### 5.1 Event Loop Integration

All modules run on Dart's single-threaded event loop:
- UDP receive → synchronous processing pipeline → UDP send.
- No multi-threading within a connection.
- Isolates used only for CPU-intensive crypto (optional optimization).

### 5.2 Processing Pipeline (Receive Path)

```
UDP datagram received
  → PacketParser.parse()           // Wire Codec
  → HeaderProtection.remove()      // Packet Engine
  → PacketProtector.decrypt()      // Packet Engine
  → FrameCodec.parseFrames()       // Wire Codec
  → dispatch frames:
    - ACK → Recovery.onAck()
    - CRYPTO → TLS.onHandshakeData()
    - STREAM → StreamManager.onStreamFrame()
    - flow control → StreamManager.onFlowControl()
    - connection → ConnectionManager.onEvent()
```

### 5.3 Processing Pipeline (Send Path)

```
Application writes data
  → StreamManager.enqueue()        // buffer data
  → StreamScheduler.next()         // pick next stream
  → FrameCodec.buildFrames()      // Wire Codec
  → PacketBuilder.build()         // Wire Codec
  → PacketProtector.encrypt()     // Packet Engine
  → HeaderProtection.apply()      // Packet Engine
  → UdpSocket.send()             // UDP I/O
  → SentPacketTracker.track()    // Recovery
```

---

## 6. Testing Architecture

Each module is independently testable:

| Module | Test Approach |
|--------|--------------|
| Wire Codec | Pure unit tests (no I/O) |
| Packet Engine | Unit tests with known keys |
| TLS Engine | Mock handshake bytes |
| Recovery | Simulated ACK sequences |
| Stream Manager | Mock frame delivery |
| Connection Manager | State machine tests |
| HTTP/3 | Mock QUIC streams |
| Integration | Full stack with loopback UDP |

---

## 7. Configuration Injection

```dart
class QuicEngineConfig {
  final QuicCryptoBackend cryptoBackend;
  final CongestionControl congestionAlgorithm;
  final QuicConfiguration transportConfig;
  final SecurityContext? securityContext;
  final Logger? logger;
}
```

All module behavior is configurable at construction time — no global state.

---

## References

- [QUIC_WIRE_SPEC.md](../specs/QUIC_WIRE_SPEC.md), [QUIC_CRYPTO_SPEC.md](../specs/QUIC_CRYPTO_SPEC.md), [QUIC_STREAMS_SPEC.md](../specs/QUIC_STREAMS_SPEC.md), [QUIC_RECOVERY_SPEC.md](../specs/QUIC_RECOVERY_SPEC.md)
- [HTTP3_SPEC.md](../specs/HTTP3_SPEC.md), [WEBTRANSPORT_SPEC.md](../specs/WEBTRANSPORT_SPEC.md), [LIBP2P_QUIC_SPEC.md](../specs/LIBP2P_QUIC_SPEC.md)
- [DART_API_SPEC.md](../specs/DART_API_SPEC.md) (public API surface)

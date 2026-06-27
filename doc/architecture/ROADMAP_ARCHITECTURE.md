---
title: "Implementation Phase Architecture"
category: architecture
version: "1.0-draft"
subsystem: "Build Order & Integration Plan"
---

# Implementation Phase Architecture



## 1. Purpose

The high-level roadmap tells us what to build and when, but not how the modules depend on each other during implementation. Without a detailed build order and milestone dependency graph, Phase 2 (HTTP/3) might start before Phase 1 (core QUIC) is testable. This architecture document bridges that gap, showing the bottom-up sequence that makes each phase demonstrable.

## 2. Build Order Rationale

The implementation order is driven by three principles:

1. **Bottom-up**: Lower layers must exist before higher layers can function.
2. **Testable at each step**: Each milestone produces a testable, demonstrable artifact.
3. **Value-first**: The earliest useful artifact is a working QUIC handshake.

---


## 3. Milestone Dependency Graph

```
                                          ┌──────────────┐
                                          │ Phase 6:     │
                                          │ dart_ipfs    │
                                          │ integration  │
                                          └──────┬───────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              │                  │                   │
                    ┌─────────▼────────┐  ┌─────▼──────┐  ┌────────▼───────┐
                    │ Phase 4:         │  │ Phase 3:   │  │ Phase 5:       │
                    │ libp2p           │  │ WebTransport│  │ Optimization   │
                    │ integration      │  │            │  │ & Hardening    │
                    └─────────┬────────┘  └─────┬──────┘  └────────┬───────┘
                              │                  │                   │
                              │           ┌──────▼──────┐           │
                              │           │ Phase 2:    │           │
                              │           │ HTTP/3      │           │
                              │           └──────┬──────┘           │
                              │                  │                   │
                              └──────────────────┼───────────────────┘
                                                 │
                                          ┌──────▼───────┐
                                          │ Phase 1:     │
                                          │ Core QUIC    │
                                          └──────┬───────┘
                                                 │
                                          ┌──────▼───────┐
                                          │ Phase 0:     │
                                          │ Specification│
                                          └──────────────┘
```

---


## 4. Phase 1 Internal Build Order

### 4.1 Milestone Sequence

```
1.1 Wire Codec
 │
 ├── 1.2 Initial Secrets + Packet Protection
 │    │
 │    └── 1.3 TLS 1.3 Integration
 │         │
 │         └── 1.4 Connection State Machine
 │              │
 │              ├── 1.5 Stream Multiplexing + Flow Control
 │              │    │
 │              │    └── 1.6 Loss Detection + Congestion Control
 │              │         │
 │              │         └── 1.7 Connection Migration
 │              │
 │              └── 1.8 0-RTT Support
 │
 └── (parallel) Test infrastructure setup
```

### 4.2 Milestone Details

#### 1.1 Wire Codec (Week 1-2)

**Builds**: `src/wire/`  
**Artifacts**:
- `VarInt.encode()` / `VarInt.decode()`
- `PacketParser.parse()` → `Packet` objects
- `FrameCodec.encode()` / `FrameCodec.decode()` for all frame types
- `PacketBuilder.build()` → bytes

**Testable**: Round-trip encode/decode of all frame types against RFC test vectors.

**No dependencies**: Pure codec, no crypto, no I/O.

#### 1.2 Initial Secrets + Packet Protection (Week 2-3)

**Builds**: `src/crypto/`  
**Artifacts**:
- `InitialSecrets.derive(dcid)` → client/server secrets
- `PacketProtector.encrypt()` / `.decrypt()`
- `HeaderProtection.apply()` / `.remove()`
- `NonceGenerator.generate(iv, packetNumber)`

**Testable**: Decrypt RFC 9001 Appendix A Initial packets.

**Depends on**: Wire Codec (for packet header parsing).

#### 1.3 TLS 1.3 Integration (Week 3-5)

**Builds**: `src/crypto/tls/`  
**Artifacts**:
- `TlsEngine` (wraps or implements TLS 1.3 state machine)
- Key schedule integration (install keys at each level)
- CRYPTO frame handling (assemble/deliver handshake messages)
- Transport parameter extension encoding/decoding

**Testable**: Complete handshake against another implementation (aioquic).

**Depends on**: Packet Protection (for encrypting/decrypting CRYPTO frames).

**Architectural decision**: Use `package:cryptography` for crypto primitives. The TLS state machine may:
- Option A: Wrap an existing TLS library (if one supports QUIC mode).
- Option B: Implement TLS 1.3 state machine in Dart (more control, more work).

Decision point: Evaluate after researching available Dart TLS libraries.

#### 1.4 Connection State Machine (Week 5-6)

**Builds**: `src/connection/`  
**Artifacts**:
- Connection lifecycle: Handshaking → Established → Closing → Closed
- `QuicEndpoint.bind()` + `.connect()` + `.connections`
- `QuicConnection` (basic, no streams yet)
- UDP socket management
- Connection ID routing

**Testable**: Establish a QUIC connection (handshake completes, 1-RTT keys installed).

**Depends on**: TLS Engine, Packet Protection.

#### 1.5 Stream Multiplexing + Flow Control (Week 6-8)

**Builds**: `src/streams/`  
**Artifacts**:
- `StreamRegistry`, `FlowController`, `ReassemblyBuffer`
- `QuicStream`, `QuicSendStream`, `QuicReceiveStream`
- Stream state machines (send/recv)
- MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS enforcement
- Data delivery to application via Dart Streams

**Testable**: Send and receive data on multiple concurrent streams.

**Depends on**: Connection Manager, Wire Codec (STREAM frames).

#### 1.6 Loss Detection + Congestion Control (Week 8-10)

**Builds**: `src/recovery/`  
**Artifacts**:
- `RttEstimator`, `LossDetector`, `SentPacketTracker`
- `NewRenoCongestionControl`
- PTO timer management
- Retransmission logic

**Testable**: Correct throughput under simulated loss; PTO fires at correct intervals.

**Depends on**: Stream Manager (retransmit stream data), Wire Codec (ACK frames).

#### 1.7 Connection Migration (Week 10-11)

**Builds**: Extension to `src/connection/`  
**Artifacts**:
- PATH_CHALLENGE / PATH_RESPONSE handling
- Address validation
- CID rotation on migration
- Anti-amplification during migration

**Testable**: Connection survives address change with path validation.

**Depends on**: All prior milestones.

#### 1.8 0-RTT Support (Week 11-12)

**Builds**: Extension to `src/crypto/tls/`  
**Artifacts**:
- Session ticket storage/retrieval
- 0-RTT packet construction
- 0-RTT acceptance/rejection handling
- API marking for early data

**Testable**: Second connection to same server uses 0-RTT.

**Depends on**: TLS Engine, Connection Manager.

---


## 5. Phase 2 Internal Build Order

```
2.1 QPACK Codec
 │
 └── 2.2 HTTP/3 Frame Layer
      │
      └── 2.3 Control Stream + SETTINGS
           │
           └── 2.4 Request/Response
                │
                ├── 2.5 Dynamic Table
                ├── 2.6 Server Push
                └── 2.7 GOAWAY
```

### Integration Point

HTTP/3 integrates with QUIC core at the `QuicConnection` level:
```dart
class Http3ClientImpl implements Http3Client {
  final QuicConnection _connection;
  late final QuicSendStream _controlStream;
  late final QuicSendStream _qpackEncoderStream;
  late final QuicReceiveStream _qpackDecoderStream;
  
  // Opens streams on the existing QUIC connection
}
```

---


## 6. Phase 4 Integration Architecture

libp2p adapter wraps the QUIC core with custom TLS behavior:

```dart
class Libp2pQuicTransportImpl implements Libp2pQuicTransport {
  Future<Libp2pConnection> dial(Multiaddr target, ...) async {
    final endpoint = await QuicEndpoint.bind(...);
    final connection = await endpoint.connect(
      target.ip!, target.port!,
      // Custom TLS verifier injected here
      securityContext: _buildLibp2pSecurityContext(hostKey),
      alpnProtocols: ['libp2p'],
    );
    
    final remotePeerId = _extractPeerId(connection);
    return Libp2pConnectionImpl(connection, remotePeerId);
  }
}
```

---


## 7. Cross-Cutting Concerns

### 7.1 Logging

Integrated from Phase 1 Milestone 1.1:
```dart
abstract class QuicLogger {
  void packet(String direction, Packet packet);
  void frame(String direction, Frame frame);
  void state(String component, String transition);
  void error(String component, Object error);
}
```

Use qlog format (JSON) for interop debugging.

### 7.2 Metrics

Exposed through `QuicConnectionStats` from Phase 1 Milestone 1.6:
```dart
class QuicConnectionStats {
  final int bytesSent, bytesReceived;
  final int packetsSent, packetsReceived, packetsLost;
  final Duration smoothedRtt, minRtt;
  final int congestionWindow, bytesInFlight;
}
```

### 7.3 Testing Infrastructure

Set up in parallel with Phase 1:
- Mock UDP socket for unit testing without network.
- Loopback transport for integration tests.
- Docker containers for interop testing.
- Benchmark harness for performance regression detection.

---


## 8. Risk Mitigations by Phase

| Phase | Risk | Mitigation |
|-------|------|-----------|
| 1.3 | TLS 1.3 complexity | Spike: evaluate existing Dart TLS libraries first |
| 1.5 | Flow control correctness | Extensive state machine testing; model checking |
| 1.6 | Congestion control tuning | Start with RFC reference algorithm; tune later |
| 2.1 | QPACK Huffman table size | Static const data; lazy initialization |
| 4.2 | Certificate generation in Dart | Spike: evaluate X.509 libraries early |
| 5 | Performance bottlenecks | Profile from Phase 1; don't defer measurement |

---


## 9. Integration Testing Between Phases

| Integration | Test |
|-------------|------|
| Wire + Crypto | Decrypt real packets from pcap |
| Crypto + Connection | Complete handshake with external impl |
| Connection + Streams | Transfer data end-to-end |
| Streams + Recovery | Recover from simulated loss |
| Core + HTTP/3 | Fetch a web page from nginx |
| Core + libp2p | Connect to go-libp2p node |
| HTTP/3 + WebTransport | WebTransport session with Chromium |

---


## 10. Parallel Work Opportunities

Within each phase, some work can proceed in parallel:

**Phase 1 parallel tracks:**
- Track A: Wire Codec → Packet Protection → TLS (serialized, foundational)
- Track B: Test infrastructure, Docker setup, CI pipeline (independent)
- Track C: Documentation, API refinement (independent)

**Phase 2+3+4 (after Phase 1):**
- HTTP/3 and libp2p adapter can proceed in parallel (both only need QUIC core).
- WebTransport depends on HTTP/3 and is sequential.

---


## 11. Definition of Done (per Milestone)

Each milestone is complete when:
1. All unit tests pass.
2. Integration test with at least one external implementation passes.
3. Code coverage meets threshold (>85%).
4. API documentation complete for public surfaces.
5. No known correctness bugs.
6. Performance baseline established.

---


## 12. References

- ROADMAP.md (timeline and phase descriptions)
- MODULE_OVERVIEW.md (module architecture)
- TESTING_SPEC.md (testing strategy)
- DATA_FLOW.md (processing pipelines)
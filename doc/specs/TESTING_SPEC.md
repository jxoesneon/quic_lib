---
title: "Testing Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Quality Assurance & Conformance"
rfc_basis: []
dependencies:
  - "ROADMAP.md"
---

# Testing Specification



## 1. Purpose

Specification without verification is just prose. dart_quic needs a multi-layer testing strategy-unit, integration, interop, fuzz-to catch regressions before they reach downstream consumers. This document defines the test levels, target implementations, and CI plan that hold the stack accountable to its own specs.

## 2. Detailed Specification
### 2.1 Testing Levels

```
┌────────────────────────────────────────────┐
│         Interoperability Tests              │  (vs quic-go, aioquic, ngtcp2)
├────────────────────────────────────────────┤
│         Integration Tests                   │  (full client-server exchanges)
├────────────────────────────────────────────┤
│         Component Tests                     │  (subsystem interactions)
├────────────────────────────────────────────┤
│         Unit Tests                          │  (individual codecs, state machines)
├────────────────────────────────────────────┤
│         Property-Based / Fuzz Tests         │  (random input resilience)
└────────────────────────────────────────────┘
```

---


### 2.2 Unit Testing

#### 2.2.1 Wire Format ([QUIC_WIRE_SPEC.md](./QUIC_WIRE_SPEC.md))

| Test | Description |
|------|-------------|
| `varint_encode_decode` | Round-trip for all boundary values |
| `varint_boundaries` | 63→64, 16383→16384, etc. |
| `long_header_parse` | All four packet types |
| `short_header_parse` | With various CID lengths |
| `frame_roundtrip_*` | Each frame type encode/decode |
| `packet_number_reconstruct` | From truncated to full |
| `coalesced_split` | Multiple packets in one datagram |

#### 2.2.2 Crypto ([QUIC_CRYPTO_SPEC.md](./QUIC_CRYPTO_SPEC.md))

| Test | Description |
|------|-------------|
| `initial_secrets_rfc_vectors` | RFC 9001 Appendix A test vectors |
| `hkdf_expand_label` | Known-answer tests |
| `aead_encrypt_decrypt` | AES-128-GCM, AES-256-GCM, ChaCha20 |
| `header_protection_roundtrip` | Apply + remove = original |
| `nonce_construction` | XOR with various packet numbers |
| `key_update_derivation` | Verify next-generation secrets |
| `retry_integrity_tag` | Verify against known Retry packet |

#### 2.2.3 Streams ([QUIC_STREAMS_SPEC.md](./QUIC_STREAMS_SPEC.md))

| Test | Description |
|------|-------------|
| `stream_id_generation` | Correct type bits for all categories |
| `send_state_machine` | All valid transitions |
| `recv_state_machine` | All valid transitions |
| `flow_control_enforcement` | Sender respects MAX_DATA |
| `reassembly_out_of_order` | Frames arrive out of sequence |
| `reassembly_overlap` | Overlapping byte ranges |
| `reset_stream_handling` | Proper state transitions |

#### 2.2.4 Recovery ([QUIC_RECOVERY_SPEC.md](./QUIC_RECOVERY_SPEC.md))

| Test | Description |
|------|-------------|
| `rtt_first_sample` | Initial smoothed_rtt and rttvar |
| `rtt_subsequent` | EWMA convergence |
| `loss_packet_threshold` | Detect at exactly gap = 3 |
| `loss_time_threshold` | Detect after 9/8 * RTT |
| `pto_computation` | Correct value with backoff |
| `congestion_slow_start` | cwnd doubles per RTT |
| `congestion_avoidance` | cwnd grows ~1 MSS per RTT |
| `congestion_loss_response` | cwnd halved on loss |
| `persistent_congestion` | Reset to minimum window |

---


### 2.3 Integration Testing

#### 2.3.1 Handshake Tests

| Test | Description |
|------|-------------|
| `basic_handshake` | 1-RTT connection establishment |
| `0rtt_handshake` | Early data with session resumption |
| `handshake_timeout` | PTO during handshake |
| `version_negotiation` | Client sends wrong version, receives VN |
| `retry_flow` | Server sends Retry, client retries |
| `alpn_negotiation` | Correct ALPN selection |
| `mutual_tls` | Both sides present certificates |

#### 2.3.2 Data Transfer Tests

| Test | Description |
|------|-------------|
| `single_stream_small` | < 1 packet of data |
| `single_stream_large` | Multiple packets, flow control updates |
| `multi_stream_concurrent` | 10+ streams simultaneously |
| `unidirectional_streams` | One-way data flow |
| `stream_reset_mid_transfer` | RESET_STREAM during data |
| `stop_sending` | Receiver requests stop |
| `connection_close_graceful` | Clean shutdown |
| `connection_close_abrupt` | Immediate close with error |

#### 2.3.3 Flow Control Tests

| Test | Description |
|------|-------------|
| `connection_flow_control` | Sender blocks at MAX_DATA |
| `stream_flow_control` | Sender blocks at MAX_STREAM_DATA |
| `stream_count_limit` | Cannot exceed MAX_STREAMS |
| `flow_control_update` | Receiver sends updates after consuming |

#### 2.3.4 Recovery Tests

| Test | Description |
|------|-------------|
| `packet_loss_recovery` | Data retransmitted on loss |
| `pto_probe` | Probe sent on PTO expiry |
| `congestion_response` | Throughput adapts to loss |
| `ecn_response` | CE marking reduces cwnd |

---


### 2.4 Interoperability Testing

#### 2.4.1 Target Implementations

| Implementation | Language | Test Mode |
|---------------|----------|-----------|
| quic-go | Go | Client + Server |
| aioquic | Python | Client + Server |
| ngtcp2 + nghttp3 | C | Client + Server |
| Chromium | C++ | Server only (via WebTransport) |

#### 2.4.2 QUIC Interop Runner

Participate in the QUIC Interop Runner (https://interop.seemann.io/):

| Test Case | Description |
|-----------|-------------|
| `handshake` | Successful 1-RTT handshake |
| `transfer` | Transfer data on multiple streams |
| `longrtt` | Function under high-latency conditions |
| `chacha20` | ChaCha20-Poly1305 cipher suite |
| `multiplexing` | Multiple concurrent streams |
| `retry` | Handle Retry packets |
| `resumption` | Session resumption (0-RTT) |
| `zerortt` | 0-RTT data transfer |
| `http3` | HTTP/3 request/response |
| `handshake_loss` | Recover from handshake packet loss |
| `transfer_loss` | Recover from data packet loss |
| `multiconnect` | Multiple connections simultaneously |
| `v2` | QUIC Version 2 (RFC 9369) |
| `ecn` | ECN marking and response |
| `datagram` | QUIC Datagram frames |

#### 2.4.3 Interop Test Infrastructure

```
┌─────────────────┐         ┌─────────────────┐
│  dart_quic      │ <-----> │  quic-go        │
│  (client/server)│  QUIC   │  (client/server)│
└─────────────────┘         └─────────────────┘
        │                           │
        └─────────┬─────────────────┘
                  │
         ┌────────┴────────┐
         │  Network Sim    │  (netem: delay, loss, reordering)
         │  (tc/netem)     │
         └─────────────────┘
```

---


### 2.5 Fuzz Testing ([FUZZING_SPEC.md](./FUZZING_SPEC.md))

#### 2.5.1 Targets

| Target | Input | Expected |
|--------|-------|----------|
| Packet parser | Random bytes | No crash; return error or valid packet |
| Frame parser | Random bytes | No crash; return error or valid frame |
| QPACK decoder | Random bytes | No crash; return error or valid headers |
| Varint decoder | Random bytes | No crash; return error or valid integer |
| Reassembly buffer | Random (offset, data) pairs | No crash; maintain invariants |

#### 2.5.2 Approach

- Use Dart's built-in test framework with random data generators.
- Run for extended periods in CI (minimum 10 minutes per target).
- Track coverage: ensure fuzz tests exercise error paths.

#### 2.5.3 Fuzz Testing Coverage Map

| Fuzz Target | Spec Reference | Coverage Goal | Seed Corpus |
|---|---|---|---|
| VarIntEncoder | [QUIC_WIRE_SPEC.md §2](#) | All 4 encoding modes | RFC 9000 Appendix A |
| PacketBuilder | [QUIC_WIRE_SPEC.md §3](#) | All 4 long-header types + short header | Generated valid frames |
| FrameParser | [QUIC_WIRE_SPEC.md §4](#) | All 22 frame types | RFC 9000 test vectors |
| StreamStateMachine | [QUIC_STREAMS_SPEC.md §3](#) | All 7 states + transitions | State transition graph |
| RecoveryEngine | [QUIC_RECOVERY_SPEC.md §2](#) | Loss detection + congestion control | Packet loss patterns |
| CryptoHandshake | [QUIC_CRYPTO_SPEC.md §3](#) | Initial + handshake + 0-RTT | RFC 9001 test vectors |
| Http3FrameParser | [HTTP3_SPEC.md §2](#) | All 6 frame types | RFC 9114 test vectors |
| QpackDecoder | [HTTP3_SPEC.md §2.4](#) | Dynamic table + blocking | RFC 9204 test vectors |
| WebTransportStream | [WEBTRANSPORT_SPEC.md §2](#) | Session + bidirectional + unidirectional | Generated sessions |
| DatagramRouter | [QUIC_DATAGRAM_SPEC.md §2](#) | Datagram frame encoding | RFC 9221 test vectors |
| DcutrCoordinator | [DCUTR_SPEC.md §2](#) | Relay + direct transition | Simulated NAT tables |
| Libp2pTls | [LIBP2P_QUIC_SPEC.md §2](#) | Certificate validation + ALPN | Test certificate chains |

> **Note:** Each fuzz target must achieve ≥90% coverage of its corresponding spec section before implementation phase.

---


### 2.6 Performance Testing ([PERFORMANCE_BENCHMARKING.md](./PERFORMANCE_BENCHMARKING.md))

#### 2.6.1 Benchmarks

| Benchmark | Metric | Target |
|-----------|--------|--------|
| `handshake_latency` | Time to establish connection | < 2x RTT + crypto overhead |
| `throughput_single_stream` | MB/s on one stream | Measure, not target (depends on HW) |
| `throughput_multi_stream` | MB/s across 100 streams | Near single-stream (no mux overhead) |
| `packet_encrypt_throughput` | Packets/second | > 100k on modern hardware |
| `varint_encode_decode` | Operations/second | > 10M |
| `qpack_encode_decode` | Headers/second | > 100k |

#### 2.6.2 Memory Profiling

- Track allocations per packet processed.
- Identify GC pressure from stream buffering.
- Verify no memory leaks on connection close.

---


### 2.7 HTTP/3 Specific Tests

#### 2.7.1 Conformance (h3spec)

Run h3spec (https://github.com/kazu-yamamoto/h3spec) test suite:

| Category | Tests |
|----------|-------|
| Connection setup | SETTINGS, control stream |
| Request/response | Methods, headers, body, trailers |
| Error handling | Invalid frames, malformed messages |
| QPACK | Static table, dynamic table, blocking |
| Stream handling | Concurrency, cancellation, push |

#### 2.7.2 dart_quic HTTP/3 Tests

| Test | Description |
|------|-------------|
| `http3_get_request` | Simple GET request/response |
| `http3_post_body` | POST with request body |
| `http3_concurrent_requests` | Multiple requests on one connection |
| `http3_server_push` | Server pushes a resource |
| `http3_goaway` | Graceful shutdown mid-requests |
| `http3_large_headers` | SETTINGS_MAX_FIELD_SECTION_SIZE enforcement |

---


### 2.8 CI Plan

#### 2.8.1 Pipeline Stages

```
┌─────────┐   ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│  Lint   │──>│  Unit   │──>│Component │──>│ Integr.  │──>│ Interop  │
│(analyze)│   │ Tests   │   │  Tests   │   │  Tests   │   │  Tests   │
└─────────┘   └─────────┘   └──────────┘   └──────────┘   └──────────┘
                                                                  │
                                                                  ▼
                                                           ┌──────────┐
                                                           │   Fuzz   │
                                                           │  (nightly)│
                                                           └──────────┘
```

#### 2.8.2 CI Configuration

| Stage | Trigger | Duration |
|-------|---------|----------|
| Lint (`dart analyze`) | Every commit | < 1 min |
| Unit tests | Every commit | < 5 min |
| Component tests | Every commit | < 10 min |
| Integration tests | Every PR | < 15 min |
| Interop tests | Nightly + release | < 30 min |
| Fuzz tests | Nightly | 10 min per target |
| Performance benchmarks | Weekly + release | < 20 min |

#### 2.8.3 Required Tools

- Dart SDK (latest stable)
- Docker (for interop test containers: quic-go, aioquic, ngtcp2)
- Network simulation (tc/netem for lossy conditions)
- h3spec binary

---


### 2.9 Coverage Requirements

| Module | Minimum Coverage |
|--------|-----------------|
| Wire codec | 95% |
| Crypto | 90% |
| Stream management | 90% |
| Loss detection | 85% |
| HTTP/3 | 85% |
| WebTransport | 80% |
| libp2p adapter | 80% |

---



## 3. Acceptance Criteria

- [ ] All unit tests pass (100% pass rate required for merge).
- [ ] Integration tests pass for basic handshake and data transfer.
- [ ] At least one interop target (quic-go) passes handshake + transfer.
- [ ] Fuzz tests run for 10 minutes without crash.
- [ ] `dart analyze` reports zero issues.
- [ ] Coverage meets or exceeds minimum thresholds.
- [ ] Performance benchmarks establish baselines (no regression targets initially).

---


## 4. Security Considerations

- Fuzz test all network-facing parsers to prevent crashes from malformed input.
- Test TLS certificate validation (accept valid, reject invalid).
- Test that sensitive data (keys, secrets) is not leaked in error messages or logs.
- Test that connections are properly cleaned up on failure (no resource leaks).

---


## 5. Dependencies

- `package:test` (Dart test framework)
- `package:mockito` or `package:mocktail` (mocking)
- Docker (interop containers)
- h3spec (HTTP/3 conformance)
- Network simulation tools (tc/netem)

---




## Used By

- [ROADMAP.md](ROADMAP.md) — Lists TESTING_SPEC as a formal specification deliverable.
## 6. References

- QUIC Interop Runner: https://interop.seemann.io/
- h3spec: https://github.com/kazu-yamamoto/h3spec
- Dart Test: https://pub.dev/packages/test
- RFC 9000 Appendix A (Test Vectors): https://www.rfc-editor.org/rfc/rfc9000#appendix-A
- RFC 9001 Appendix A (Crypto Test Vectors): https://www.rfc-editor.org/rfc/rfc9001#appendix-A
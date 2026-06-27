# Testing Specification

**Version**: 1.0-draft  
**Status**: Specification  
**Subsystem**: Quality Assurance & Conformance

---

## 1. Purpose

This document specifies the testing strategy for `dart_quic`: conformance testing against RFC examples, interoperability testing against established QUIC implementations, fuzz testing, and the CI plan.

---

## 2. Testing Levels

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

## 3. Unit Testing

### 3.1 Wire Format (QUIC_WIRE_SPEC.md)

| Test | Description |
|------|-------------|
| `varint_encode_decode` | Round-trip for all boundary values |
| `varint_boundaries` | 63→64, 16383→16384, etc. |
| `long_header_parse` | All four packet types |
| `short_header_parse` | With various CID lengths |
| `frame_roundtrip_*` | Each frame type encode/decode |
| `packet_number_reconstruct` | From truncated to full |
| `coalesced_split` | Multiple packets in one datagram |

### 3.2 Crypto (QUIC_CRYPTO_SPEC.md)

| Test | Description |
|------|-------------|
| `initial_secrets_rfc_vectors` | RFC 9001 Appendix A test vectors |
| `hkdf_expand_label` | Known-answer tests |
| `aead_encrypt_decrypt` | AES-128-GCM, AES-256-GCM, ChaCha20 |
| `header_protection_roundtrip` | Apply + remove = original |
| `nonce_construction` | XOR with various packet numbers |
| `key_update_derivation` | Verify next-generation secrets |
| `retry_integrity_tag` | Verify against known Retry packet |

### 3.3 Streams (QUIC_STREAMS_SPEC.md)

| Test | Description |
|------|-------------|
| `stream_id_generation` | Correct type bits for all categories |
| `send_state_machine` | All valid transitions |
| `recv_state_machine` | All valid transitions |
| `flow_control_enforcement` | Sender respects MAX_DATA |
| `reassembly_out_of_order` | Frames arrive out of sequence |
| `reassembly_overlap` | Overlapping byte ranges |
| `reset_stream_handling` | Proper state transitions |

### 3.4 Recovery (QUIC_RECOVERY_SPEC.md)

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

## 4. Integration Testing

### 4.1 Handshake Tests

| Test | Description |
|------|-------------|
| `basic_handshake` | 1-RTT connection establishment |
| `0rtt_handshake` | Early data with session resumption |
| `handshake_timeout` | PTO during handshake |
| `version_negotiation` | Client sends wrong version, receives VN |
| `retry_flow` | Server sends Retry, client retries |
| `alpn_negotiation` | Correct ALPN selection |
| `mutual_tls` | Both sides present certificates |

### 4.2 Data Transfer Tests

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

### 4.3 Flow Control Tests

| Test | Description |
|------|-------------|
| `connection_flow_control` | Sender blocks at MAX_DATA |
| `stream_flow_control` | Sender blocks at MAX_STREAM_DATA |
| `stream_count_limit` | Cannot exceed MAX_STREAMS |
| `flow_control_update` | Receiver sends updates after consuming |

### 4.4 Recovery Tests

| Test | Description |
|------|-------------|
| `packet_loss_recovery` | Data retransmitted on loss |
| `pto_probe` | Probe sent on PTO expiry |
| `congestion_response` | Throughput adapts to loss |
| `ecn_response` | CE marking reduces cwnd |

---

## 5. Interoperability Testing

### 5.1 Target Implementations

| Implementation | Language | Test Mode |
|---------------|----------|-----------|
| quic-go | Go | Client + Server |
| aioquic | Python | Client + Server |
| ngtcp2 + nghttp3 | C | Client + Server |
| Chromium | C++ | Server only (via WebTransport) |

### 5.2 QUIC Interop Runner

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

### 5.3 Interop Test Infrastructure

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

## 6. Fuzz Testing

### 6.1 Targets

| Target | Input | Expected |
|--------|-------|----------|
| Packet parser | Random bytes | No crash; return error or valid packet |
| Frame parser | Random bytes | No crash; return error or valid frame |
| QPACK decoder | Random bytes | No crash; return error or valid headers |
| Varint decoder | Random bytes | No crash; return error or valid integer |
| Reassembly buffer | Random (offset, data) pairs | No crash; maintain invariants |

### 6.2 Approach

- Use Dart's built-in test framework with random data generators.
- Run for extended periods in CI (minimum 10 minutes per target).
- Track coverage: ensure fuzz tests exercise error paths.

---

## 7. Performance Testing

### 7.1 Benchmarks

| Benchmark | Metric | Target |
|-----------|--------|--------|
| `handshake_latency` | Time to establish connection | < 2x RTT + crypto overhead |
| `throughput_single_stream` | MB/s on one stream | Measure, not target (depends on HW) |
| `throughput_multi_stream` | MB/s across 100 streams | Near single-stream (no mux overhead) |
| `packet_encrypt_throughput` | Packets/second | > 100k on modern hardware |
| `varint_encode_decode` | Operations/second | > 10M |
| `qpack_encode_decode` | Headers/second | > 100k |

### 7.2 Memory Profiling

- Track allocations per packet processed.
- Identify GC pressure from stream buffering.
- Verify no memory leaks on connection close.

---

## 8. HTTP/3 Specific Tests

### 8.1 Conformance (h3spec)

Run h3spec (https://github.com/kazu-yamamoto/h3spec) test suite:

| Category | Tests |
|----------|-------|
| Connection setup | SETTINGS, control stream |
| Request/response | Methods, headers, body, trailers |
| Error handling | Invalid frames, malformed messages |
| QPACK | Static table, dynamic table, blocking |
| Stream handling | Concurrency, cancellation, push |

### 8.2 dart_quic HTTP/3 Tests

| Test | Description |
|------|-------------|
| `http3_get_request` | Simple GET request/response |
| `http3_post_body` | POST with request body |
| `http3_concurrent_requests` | Multiple requests on one connection |
| `http3_server_push` | Server pushes a resource |
| `http3_goaway` | Graceful shutdown mid-requests |
| `http3_large_headers` | SETTINGS_MAX_FIELD_SECTION_SIZE enforcement |

---

## 9. CI Plan

### 9.1 Pipeline Stages

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

### 9.2 CI Configuration

| Stage | Trigger | Duration |
|-------|---------|----------|
| Lint (`dart analyze`) | Every commit | < 1 min |
| Unit tests | Every commit | < 5 min |
| Component tests | Every commit | < 10 min |
| Integration tests | Every PR | < 15 min |
| Interop tests | Nightly + release | < 30 min |
| Fuzz tests | Nightly | 10 min per target |
| Performance benchmarks | Weekly + release | < 20 min |

### 9.3 Required Tools

- Dart SDK (latest stable)
- Docker (for interop test containers: quic-go, aioquic, ngtcp2)
- Network simulation (tc/netem for lossy conditions)
- h3spec binary

---

## 10. Coverage Requirements

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

## 11. Acceptance Criteria

- [ ] All unit tests pass (100% pass rate required for merge).
- [ ] Integration tests pass for basic handshake and data transfer.
- [ ] At least one interop target (quic-go) passes handshake + transfer.
- [ ] Fuzz tests run for 10 minutes without crash.
- [ ] `dart analyze` reports zero issues.
- [ ] Coverage meets or exceeds minimum thresholds.
- [ ] Performance benchmarks establish baselines (no regression targets initially).

---

## 12. Security Considerations

- Fuzz test all network-facing parsers to prevent crashes from malformed input.
- Test TLS certificate validation (accept valid, reject invalid).
- Test that sensitive data (keys, secrets) is not leaked in error messages or logs.
- Test that connections are properly cleaned up on failure (no resource leaks).

---

## 13. Dependencies

- `package:test` (Dart test framework)
- `package:mockito` or `package:mocktail` (mocking)
- Docker (interop containers)
- h3spec (HTTP/3 conformance)
- Network simulation tools (tc/netem)

---

## References

- QUIC Interop Runner: https://interop.seemann.io/
- h3spec: https://github.com/kazu-yamamoto/h3spec
- Dart Test: https://pub.dev/packages/test
- RFC 9000 Appendix A (Test Vectors): https://www.rfc-editor.org/rfc/rfc9000#appendix-A
- RFC 9001 Appendix A (Crypto Test Vectors): https://www.rfc-editor.org/rfc/rfc9001#appendix-A

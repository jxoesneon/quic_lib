# dart_quic Project Roadmap: v0.0.0 → v1.0.0

**Version**: 1.0
**Status**: Finalized
**Last Updated**: 2026-06-27
**Constraint**: Pure-Dart implementation per [ADR-001](decisions/ADR-001_Pure_Dart_No_FFI.md). No `dart:ffi`, no native dependencies.

---

## 1. Purpose

This document coordinates the engineering journey from specification (v0.0.0) to production-stable v1.0.0. It records version bumps, deliverables, acceptance gates, and risk mitigations so that contributors share a common plan.

---

## 2. Roadmap Philosophy

### 2.1 Versioning Strategy

We follow [Semantic Versioning](https://semver.org/) with pre-release identifiers:

| Identifier | Meaning |
|---|---|
| `-alpha.N` | Feature incomplete. APIs may change without notice. Internal dogfooding only. |
| `-beta.N` | Feature complete. APIs stabilizing. External early adopters welcome with breakage warnings. |
| `-rc.N` | Release candidate. API frozen. Only bug fixes and documentation polish. |
| (no suffix) | Stable. Breaking changes require major version bump. |

### 2.2 Phase-Version Mapping

| Phase | Version Range | Theme |
|---|---|---|
| Phase 0 | v0.0.0 | Specification (COMPLETE) |
| Phase 1 | v0.1.0-alpha → v0.3.0-alpha | Core QUIC transport |
| Phase 2 | v0.4.0-alpha → v0.5.0-alpha | HTTP/3 & WebTransport |
| Phase 3 | v0.6.0-alpha | libp2p QUIC & DCUtR |
| Phase 4 | v0.7.0-beta → v0.9.0-beta | Hardening, fuzzing, performance |
| Phase 5 | v1.0.0-rc.1 → v1.0.0-rc.2 | Release candidates |
| Phase 6 | v1.0.0 | Stable production release |

### 2.3 Exit Gates (Universal)

Every release must pass these gates before the version tag is applied:

1. **CI Green**: All automated tests pass on `ubuntu-latest`, `macos-latest`, `windows-latest`.
2. **Lint Clean**: `dart analyze` zero issues, `dart format --set-exit-if-changed` passes.
3. **Coverage Floor**: Unit test coverage ≥ 70% for alpha, ≥ 80% for beta, ≥ 90% for rc/stable.
4. **Spec Compliance**: Each implemented feature has a corresponding spec acceptance criterion marked `[x]`.
5. **No Regressions**: Previous phase interop tests still pass.

---

## 3. Detailed Release Plan

### 3.1 v0.0.0 — Specification Complete

**Status**: DONE
**Tag**: `v0.0.0`
**Date**: 2026-06-27

**Deliverables**:
- 21 formal specifications in `doc/specs/`
- 9 research notes in `doc/research/`
- 6 architecture documents in `doc/architecture/`
- 7 accepted ADRs in `doc/decisions/`
- `SECURITY.md`, `CHANGELOG.md`, `INDEX.md`, `EXTENSION_GUIDE.md`
- CI workflow template (`.github/workflows/ci.yml`)

**Exit Gate**: Core maintainers review and confirm specification completeness and consistency.

---

### 3.2 v0.1.0-alpha.1 — Wire Format & Crypto Skeleton

**Target Date**: Month 1–2
**Duration**: 4–6 weeks
**Theme**: "If you can't parse a packet, you can't ship anything."

**Deliverables**:
- `pubspec.yaml` with `package:cryptography` dependency (per ADR-004).
- `lib/src/wire/` — varint encoder/decoder, packet header parser/serializer.
- `lib/src/crypto/` — HKDF-Expand-Label, Initial secret derivation, AES-128-GCM packet protection.
- `lib/src/transport_parameters.dart` — wire encoding/decoding of all RFC 9000 parameters.
- Unit tests for every encode/decode pair in [QUIC_WIRE_SPEC.md](specs/QUIC_WIRE_SPEC.md) and [QUIC_CRYPTO_SPEC.md](specs/QUIC_CRYPTO_SPEC.md).
- Test vectors from [TEST_VECTORS.md](specs/TEST_VECTORS.md) passing.

**API Surface**:
- Internal-only. No public API exported from `lib/dart_quic.dart`.

**Acceptance Criteria**:
- [ ] VarInt round-trip for all 4 encoding modes.
- [ ] Initial secret derivation matches RFC 9001 Appendix A test vectors.
- [ ] Packet protection round-trip: encrypt → decrypt yields identical payload.
- [ ] Transport parameter encoding/decoding handles all 17 core parameters plus extensions.
- [ ] `dart analyze` zero issues.

**Risk Mitigation**:
- **Risk**: `package:cryptography` missing a required primitive. **Mitigation**: Fallback to `package:pointycastle` per ADR-004; if both fail, escalate to ADR revision.
- **Risk**: Performance of pure-Dart crypto unacceptable. **Mitigation**: Benchmark early; if >5x slower than rustls, investigate algorithm-level optimizations (not FFI).

**Interop Milestone**: None (internal only).

---

### 3.3 v0.1.0-alpha.2 — Connection Establishment (Handshake)

**Target Date**: Month 2–3
**Duration**: 3–4 weeks
**Depends On**: v0.1.0-alpha.1

**Deliverables**:
- `lib/src/connection.dart` — Connection state machine (idle → handshake → established → closing → closed).
- `lib/src/handshake/` — TLS 1.3 handshake integration via `dart:io` `SecureSocket` or `package:cryptography` TLS layer.
- `lib/src/frame/` — All 22 frame types from [QUIC_WIRE_SPEC.md §2.3](specs/QUIC_WIRE_SPEC.md#23-frame-types-rfc-9000-section-19) parsed and serialized.
- Retry token generation and validation.
- Address validation (anti-amplification, PATH_CHALLENGE/PATH_RESPONSE).

**API Surface**:
- Internal-only. No public API.

**Acceptance Criteria**:
- [ ] Client can send Initial, receive Retry, re-send with token, complete handshake.
- [ ] Server can receive Initial, send Retry, accept valid token, complete handshake.
- [ ] Anti-amplification limit enforced: ≤ 3x bytes sent before validation.
- [ ] All 22 frame types round-trip through parser/serializer.
- [ ] Connection state machine transitions match [QUIC_STREAMS_SPEC.md §2.1](specs/QUIC_STREAMS_SPEC.md#21-connection-lifecycle).

**Interop Milestone**:
- [ ] Handshake completes against `quic-go` echo server (dockerized).
- [ ] Handshake completes against `aioquic` echo server (dockerized).

---

### 3.4 v0.2.0-alpha — Streams, Flow Control, & 0-RTT

**Target Date**: Month 3–4
**Duration**: 4–5 weeks
**Depends On**: v0.1.0-alpha.2

**Deliverables**:
- `lib/src/stream.dart` — Stream state machine, ID allocation, bidirectional and unidirectional streams.
- `lib/src/flow_control.dart` — MAX_DATA, MAX_STREAM_DATA enforcement; WINDOW_UPDATE generation.
- `lib/src/early_data.dart` — 0-RTT key derivation, session ticket storage, `isEarlyData` API marking.
- `lib/src/migration.dart` — Connection ID rotation, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, path validation.

**API Surface (First Public)**:
```dart
// lib/dart_quic.dart
export 'src/quic_endpoint.dart' show QuicEndpoint;
export 'src/quic_connection.dart' show QuicConnection;
export 'src/quic_stream.dart' show QuicStream, QuicSendStream, QuicReceiveStream;
export 'src/quic_configuration.dart' show QuicConfiguration;
```

**Acceptance Criteria**:
- [ ] Client can open 100 concurrent bidirectional streams without error.
- [ ] Flow control prevents sender from exceeding peer's MAX_STREAM_DATA.
- [ ] 0-RTT data is marked `isEarlyData == true` and is replayable by design.
- [ ] Connection migration to new IP/port completes with PATH_CHALLENGE/PATH_RESPONSE.
- [ ] Stateless reset token generation matches [SECURITY_SPEC.md §2.8.2](specs/SECURITY_SPEC.md#282-stateless-reset).

**Interop Milestone**:
- [ ] Stream data round-trip against `quic-go` (1 MB transfer).
- [ ] 0-RTT resumption against `ngtcp2` server.

---

### 3.5 v0.3.0-alpha — Recovery, Loss Detection, NewReno

**Target Date**: Month 4–5
**Duration**: 3–4 weeks
**Depends On**: v0.2.0-alpha

**Deliverables**:
- `lib/src/recovery/` — RTT estimator, loss detection (packet threshold + time threshold), PTO scheduler.
- `lib/src/congestion/new_reno.dart` — NewReno congestion control (per ADR-002: NewReno before CUBIC).
- `lib/src/ack.dart` — ACK frame generation with ACK ranges, delayed ACK strategy.
- Packet number spaces (Initial, Handshake, Application Data) tracked independently.

**API Surface**:
- Add `QuicConnectionStats` to public API:
  ```dart
  class QuicConnectionStats {
    Duration get smoothedRtt;
    int get bytesInFlight;
    int get congestionWindow;
    int get packetsLost;
  }
  ```

**Acceptance Criteria**:
- [ ] RTT estimation matches RFC 9002 test scenarios within 1ms.
- [ ] Loss detection triggers retransmission within 1 PTO of expected ACK.
- [ ] NewReno cwnd growth follows slow-start then congestion-avoidance curve.
- [ ] ACK frame correctly encodes up to 256 ACK ranges.
- [ ] Stats API reflects real-time connection state.

**Interop Milestone**:
- [ ] Transfer 10 MB file against `quic-go` with 2% simulated packet loss; throughput > 50% of lossless baseline.

---

### 3.6 v0.4.0-alpha — HTTP/3 Client

**Target Date**: Month 5–6
**Duration**: 3–4 weeks
**Depends On**: v0.3.0-alpha

**Deliverables**:
- `lib/src/http3/` — HTTP/3 frame parser (HEADERS, DATA, SETTINGS, GOAWAY, PRIORITY_UPDATE per [HTTP3_SPEC.md](specs/HTTP3_SPEC.md)).
- `lib/src/http3/client.dart` — `Http3Client` with `connect()`, `send()`, `get()`, `post()`.
- `lib/src/qpack/` — QPACK encoder/decoder with static table (99 entries), dynamic table, encoder/decoder instructions.
- `lib/src/http3/settings.dart` — SETTINGS frame negotiation.

**API Surface**:
```dart
// lib/http3.dart
export 'src/http3/http3_client.dart' show Http3Client;
export 'src/http3/http3_request.dart' show Http3Request;
export 'src/http3/http3_response.dart' show Http3Response;
export 'src/http3/http3_settings.dart' show Http3Settings;
```

**Acceptance Criteria**:
- [ ] HTTP/3 GET request to `https://cloudflare-quic.com` succeeds (200 OK).
- [ ] QPACK static table resolves all 99 entries correctly.
- [ ] Dynamic table insertion/eviction follows capacity rules.
- [ ] SETTINGS negotiation completes before first request.
- [ ] GOAWAY graceful shutdown drains active streams.

**Interop Milestone**:
- [ ] Pass `h3spec` client tests (if available) against internal server stub.
- [ ] Fetch 1000 requests sequentially against public HTTP/3 endpoint without error.

---

### 3.7 v0.5.0-alpha — HTTP/3 Server, WebTransport, & Datagrams

**Target Date**: Month 6–7
**Duration**: 4–5 weeks
**Depends On**: v0.4.0-alpha

**Deliverables**:
- `lib/src/http3/server.dart` — `Http3Server` with `bind()`, stream request handler.
- `lib/src/webtransport/` — WebTransport session establishment (extended CONNECT), capsule protocol, datagrams.
- `lib/src/datagram.dart` — QUIC datagram extension (RFC 9221) frame format, API integration.
- `lib/src/webtransport/client.dart` — `WebTransportClient`.
- `lib/src/webtransport/server.dart` — `WebTransportServer`.

**API Surface**:
```dart
// lib/http3.dart (additions)
export 'src/http3/http3_server.dart' show Http3Server, Http3ServerRequest, Http3ServerResponse;

// lib/webtransport.dart
export 'src/webtransport/web_transport_client.dart' show WebTransportClient;
export 'src/webtransport/web_transport_session.dart' show WebTransportSession;
export 'src/webtransport/web_transport_bidi_stream.dart' show WebTransportBidiStream;
export 'src/webtransport/web_transport_datagram.dart' show WebTransportDatagram;
```

**Acceptance Criteria**:
- [ ] HTTP/3 server serves a simple static file over QUIC.
- [ ] WebTransport client connects to `https://webtransport.day` (or equivalent test server).
- [ ] WebTransport bidirectional stream round-trips 1 MB.
- [ ] Datagrams send/receive 1000 packets without ordering guarantees.
- [ ] Priority signaling (RFC 9218) influences stream scheduling.

**Interop Milestone**:
- [ ] HTTP/3 server passes `h3spec` server tests.
- [ ] WebTransport interop with Chromium test server.

---

### 3.8 v0.6.0-alpha — libp2p QUIC, DCUtR, & CUBIC

**Target Date**: Month 7–8
**Duration**: 4–5 weeks
**Depends On**: v0.5.0-alpha

**Deliverables**:
- `lib/src/libp2p/` — libp2p TLS 1.3 extension (self-signed certs, PeerId verification), ALPN negotiation.
- `lib/src/libp2p/transport.dart` — `Libp2pQuicTransport` with `dial()` and `listen()`.
- `lib/src/libp2p/multiaddr.dart` — Multiaddr parsing for `/quic-v1` and `/p2p-circuit`.
- `lib/src/libp2p/dcutr.dart` — DCUtR coordinator: relayed → direct connection upgrade.
- `lib/src/congestion/cubic.dart` — CUBIC congestion control (per ADR-002, replaces NewReno as default).
- Multistream-select protocol negotiation over QUIC streams.

**API Surface**:
```dart
// lib/libp2p.dart
export 'src/libp2p/libp2p_quic_transport.dart' show Libp2pQuicTransport;
export 'src/libp2p/libp2p_connection.dart' show Libp2pConnection;
export 'src/libp2p/libp2p_stream.dart' show Libp2pStream;
export 'src/libp2p/peer_id.dart' show PeerId;
export 'src/libp2p/multiaddr.dart' show Multiaddr;
```

**Acceptance Criteria**:
- [ ] libp2p QUIC handshake with `go-libp2p` peer succeeds and verifies PeerId.
- [ ] DCUtR cuts over from relayed to direct connection within 5 seconds (simulated NAT).
- [ ] CUBIC throughput exceeds NewReno by ≥ 10% on high-BDP simulated link.
- [ ] Multistream-select negotiates `/ipfs/kad/1.0.0` successfully.
- [ ] Self-signed certificate generation follows [LIBP2P_QUIC_SPEC.md §2.3](specs/LIBP2P_QUIC_SPEC.md#23-tls-13-peer-authentication).

**Interop Milestone**:
- [ ] Connect to Kubo (go-ipfs) node via `/quic-v1` multiaddr.
- [ ] DCUtR interop with `go-libp2p` DCUtR implementation.

---

### 3.9 v0.7.0-beta — Feature Freeze & API Stabilization

**Target Date**: Month 8–9
**Duration**: 3–4 weeks
**Depends On**: v0.6.0-alpha
**Theme**: "No new features. Only stabilization."

**Deliverables**:
- All public APIs marked `@stable` or `@experimental`.
- `dartdoc` generated with 100% public API coverage.
- Breaking change inventory published in `CHANGELOG.md`.
- `dart_ipfs` integration contract validated: compile `dart_ipfs` against `dart_quic` v0.7.0-beta with zero breaking changes.
- Transport parameter validation hardened: all 17 core parameters + extensions validated per [QUIC_TRANSPORT_PARAMETERS_SPEC.md](specs/QUIC_TRANSPORT_PARAMETERS_SPEC.md).

**API Surface**: Frozen. Only non-breaking additions allowed.

**Acceptance Criteria**:
- [ ] Zero breaking changes since v0.6.0-alpha (verified by CI diff).
- [ ] Dartdoc builds without warnings.
- [ ] `dart_ipfs` compiles and passes its own unit tests using `dart_quic` v0.7.0-beta.
- [ ] All public APIs have dartdoc comments.

**Risk Mitigation**:
- **Risk**: `dart_ipfs` team reports API mismatch. **Mitigation**: 2-week API revision window; if breaking changes required, they go into v0.8.0-beta, not v0.7.0.

---

### 3.10 v0.8.0-beta — Fuzzing Campaign & Security Audit

**Target Date**: Month 9–10
**Duration**: 4–5 weeks
**Depends On**: v0.7.0-beta

**Deliverables**:
- `test/fuzz/` — Fuzzing harnesses for all 12 targets in [FUZZING_SPEC.md](specs/FUZZING_SPEC.md).
- `test/security/` — STRIDE-mapped penetration tests.
- External security audit commissioned (per [SECURITY_SPEC.md §2.13](specs/SECURITY_SPEC.md#213-supply-chain-security)).
- OSS-Fuzz integration submitted (if accepted by Google).
- CVE monitoring enabled via Dependabot/OSV-Scanner.
- All findings from security audit triaged: critical/high fixed, medium/low documented with mitigations.

**Acceptance Criteria**:
- [ ] Each fuzz target runs ≥ 1 billion iterations with zero crashes.
- [ ] Security audit report published (redacted if necessary).
- [ ] Zero critical or high-severity vulnerabilities open.
- [ ] SBOM (SPDX JSON) generated and attached to release.

**Interop Milestone**:
- [ ] Pass QUIC interop runner tests (if available) for at least 3 independent implementations.

---

### 3.11 v0.9.0-beta — Performance Optimization & Benchmarks

**Target Date**: Month 10–11
**Duration**: 3–4 weeks
**Depends On**: v0.8.0-beta

**Deliverables**:
- `benchmark/` — Micro-benchmarks for varint encode, frame parse, crypto ops, stream throughput.
- `benchmark/` — Macro-benchmarks: HTTP/3 file download, WebTransport datagram flood, libp2p DHT query.
- Performance regression CI gate: any PR that regresses benchmarks by > 5% is blocked.
- Isolate-per-connection architecture tuned per [ADR-007](decisions/ADR-007_Isolate_per_Connection_Architecture.md).
- Memory profiling: no leaks detected in 24-hour soak test.

**Targets** (from [PERFORMANCE_BENCHMARKING.md](specs/PERFORMANCE_BENCHMARKING.md)):
| Metric | Target |
|---|---|
| VarInt encode/decode | < 50 ns/op |
| 1-RTT handshake | < 100 ms (localhost) |
| Stream throughput | > 500 Mbps (localhost) |
| Memory per connection | < 4 MB |
| Concurrent connections | > 10,000 |

**Acceptance Criteria**:
- [ ] All macro-benchmarks meet or exceed baseline targets.
- [ ] 24-hour soak test: no memory growth > 1%.
- [ ] Performance regression CI gate active and passing.
- [ ] `dart compile exe` AOT binary size < 5 MB (core library only).

---

### 3.12 v1.0.0-rc.1 — Release Candidate 1

**Target Date**: Month 11–12
**Duration**: 2–3 weeks
**Depends On**: v0.9.0-beta
**Theme**: "Code freeze. Find the last bugs."

**Deliverables**:
- Feature freeze. No new code except bug fixes.
- All open issues labeled `v1.0.0-blocker` resolved.
- Migration guide from v0.9.0-beta to v1.0.0-rc.1 published.
- `dart_ipfs` integration validated end-to-end: full IPFS node using `dart_quic` as transport.
- Examples directory: `example/echo/`, `example/http3_client/`, `example/webtransport_chat/`, `example/libp2p_dial/`.

**Acceptance Criteria**:
- [ ] Zero open `v1.0.0-blocker` issues.
- [ ] All examples run without modification on Windows, macOS, Linux.
- [ ] `dart_ipfs` can bootstrap to the public IPFS swarm using `dart_quic`.

---

### 3.13 v1.0.0-rc.2 — Release Candidate 2

**Target Date**: Month 12–13
**Duration**: 2 weeks
**Depends On**: v1.0.0-rc.1

**Deliverables**:
- Bug fixes from rc.1 feedback only.
- Final documentation review: all specs updated to reflect implementation reality (any deviations documented as ADR revisions).
- Website/docs landing page published (GitHub Pages or similar).
- Pub.dev package published as `dart_quic: 1.0.0-rc.2`.

**Acceptance Criteria**:
- [ ] Zero new bugs reported in rc.1 within 1 week of release.
- [ ] Pub.dev score ≥ 140/150 (documentation, static analysis, maintenance).
- [ ] All specs promoted from `1.0` to `1.0-final` with implementation notes.

---

### 3.14 v1.0.0 — Stable Production Release

**Target Date**: Month 13
**Tag**: `v1.0.0`
**Depends On**: v1.0.0-rc.2

**Deliverables**:
- `dart_quic` v1.0.0 published to pub.dev.
- GitHub Release with changelog, SBOM, and migration guide.
- Announcement blog post / tweet thread.
- `dart_ipfs` depends on `dart_quic: ^1.0.0`.
- Long-term support commitment: security fixes backported for 12 months.

**Acceptance Criteria**:
- [ ] 30 days since rc.2 with zero critical bugs.
- [ ] ≥ 3 downstream projects (including `dart_ipfs`) using v1.0.0 in production.
- [ ] Core maintainers conduct a post-mortem and confirm the release meets quality criteria.

---

## 4. Version Summary Table

| Version | Phase | Duration | Theme | Public API? |
|---|---|---|---|---|
| v0.0.0 | 0 | DONE | Specification | No |
| v0.1.0-alpha.1 | 1 | 4–6 wk | Wire + Crypto | No |
| v0.1.0-alpha.2 | 1 | 3–4 wk | Handshake | No |
| v0.2.0-alpha | 1 | 4–5 wk | Streams + 0-RTT | Yes (core) |
| v0.3.0-alpha | 1 | 3–4 wk | Recovery + NewReno | Yes (core) |
| v0.4.0-alpha | 2 | 3–4 wk | HTTP/3 Client | Yes (+http3) |
| v0.5.0-alpha | 2 | 4–5 wk | HTTP/3 Server + WebTransport | Yes (+webtransport) |
| v0.6.0-alpha | 3 | 4–5 wk | libp2p + DCUtR + CUBIC | Yes (+libp2p) |
| v0.7.0-beta | 4 | 3–4 wk | API Freeze | Yes (stable) |
| v0.8.0-beta | 4 | 4–5 wk | Fuzz + Security Audit | Yes (stable) |
| v0.9.0-beta | 4 | 3–4 wk | Performance | Yes (stable) |
| v1.0.0-rc.1 | 5 | 2–3 wk | RC 1 | Yes (frozen) |
| v1.0.0-rc.2 | 5 | 2 wk | RC 2 | Yes (frozen) |
| v1.0.0 | 6 | — | Stable | Yes (production) |

---

## 5. Dependencies & Critical Path

```
v0.0.0 ──→ v0.1.0-alpha.1 ──→ v0.1.0-alpha.2 ──→ v0.2.0-alpha ──→ v0.3.0-alpha
  │              │                    │                  │                │
  │              └─[Wire/Crypto]──────┴─[Handshake]──────┴─[Streams]──────┴─[Recovery]
  │
  └──→ v0.4.0-alpha ──→ v0.5.0-alpha ──→ v0.6.0-alpha
            │                │                │
            └─[HTTP/3 cl]────┴─[HTTP/3 srv+WT]─┴─[libp2p+DCUtR]
                                          │
                                          ▼
                               v0.7.0-beta ──→ v0.8.0-beta ──→ v0.9.0-beta
                                 [Freeze]       [Security]       [Perf]
                                          │
                                          ▼
                               v1.0.0-rc.1 ──→ v1.0.0-rc.2 ──→ v1.0.0
                                 [RC1]          [RC2]          [Stable]
```

**Critical Path**: v0.1.0-alpha.1 → v0.1.0-alpha.2 → v0.2.0-alpha → v0.3.0-alpha → v0.6.0-alpha → v0.7.0-beta → v0.8.0-beta → v1.0.0-rc.1 → v1.0.0

Any delay on the critical path pushes v1.0.0. Non-critical phases (HTTP/3, WebTransport) can slip without affecting the stable date if they are feature-flagged.

---

## 6. Risk Register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Pure-Dart crypto too slow | Medium | High | Benchmark at v0.1.0; optimize algorithms; never use FFI per ADR-001. |
| TLS 1.3 library immature in Dart | Medium | High | Fallback to `dart:io` SecureSocket for handshake; custom record layer for QUIC. |
| libp2p spec drift | Low | Medium | Subscribe to libp2p spec changes; 2-week buffer in Phase 3. |
| Security audit finds critical flaw | Medium | High | 4-week buffer before rc.1; all critical findings block release. |
| `dart_ipfs` API demands break dart_quic | Medium | Medium | Integration contract locked at v0.7.0-beta; breaking changes require ADR. |
| Maintainer bandwidth drops | Medium | High | Document everything; any Dart developer can pick up a spec and implement. |
| Interop test infrastructure unavailable | Low | Medium | Dockerize reference implementations; maintain internal test lab. |

---

## 7. Resource Requirements

| Phase | Engineers | Duration | Total Person-Weeks |
|---|---|---|---|
| v0.1.0-alpha.1–2 | 1–2 | 7–10 wk | 10–20 |
| v0.2.0–v0.3.0-alpha | 2 | 7–9 wk | 14–18 |
| v0.4.0–v0.5.0-alpha | 2 | 7–9 wk | 14–18 |
| v0.6.0-alpha | 2–3 | 4–5 wk | 8–15 |
| v0.7.0–v0.9.0-beta | 2 | 10–13 wk | 20–26 |
| v1.0.0-rc.1–2 | 1–2 | 4–5 wk | 4–10 |
| **Total** | — | **~13 months** | **~70–107 person-weeks** |

**Minimum viable team**: 2 full-time Dart engineers + 1 part-time security reviewer.
**Ideal team**: 3 full-time engineers + 1 technical writer + 1 security auditor (contract).

---

## 8. Governance

### 8.1 Release Manager

Each release has a designated Release Manager responsible for:
- Cutting the version branch (`release/v0.X.Y`).
- Running the exit gate checklist.
- Publishing the GitHub Release and pub.dev package.
- Communicating breaking changes to `dart_ipfs` maintainers.

### 8.2 Release Review Checkpoints

The maintainers review at these mandatory checkpoints:
1. **Post-v0.3.0-alpha**: Core transport completeness.
2. **Post-v0.6.0-alpha**: Full feature completeness.
3. **Pre-v0.7.0-beta**: API freeze approval.
4. **Post-v0.8.0-beta**: Security audit acceptance.
5. **Pre-v1.0.0**: Final release readiness.

### 8.3 Change Control After v0.7.0-beta

After the API freeze:
- **Patch releases** (v0.7.1, v0.8.1, etc.): Bug fixes only. Release Manager approves.
- **Minor releases** (v0.8.0, v0.9.0): Non-breaking additions. Maintainer majority approves.
- **Major changes**: Require ADR and maintainer consensus.

---

## 9. References

- [ROADMAP.md](specs/ROADMAP.md) — Specification-phase deliverables (Phase 0).
- [VERSIONING_POLICY.md](specs/VERSIONING_POLICY.md) — SemVer rules, promotion criteria, backport policy.
- [SECURITY_SPEC.md](specs/SECURITY_SPEC.md) — Threat model, STRIDE analysis, security requirements.
- [PERFORMANCE_BENCHMARKING.md](specs/PERFORMANCE_BENCHMARKING.md) — Benchmark methodology and targets.
- [FUZZING_SPEC.md](specs/FUZZING_SPEC.md) — Fuzz targets, harness design, CI integration.
- [DART_API_SPEC.md](specs/DART_API_SPEC.md) — Public API surface definitions.
- [ADR-001](decisions/ADR-001_Pure_Dart_No_FFI.md) — Pure-Dart constraint.
- [ADR-002](decisions/ADR-002_NewReno_Before_CUBIC.md) — Congestion control ordering.
- [ADR-004](decisions/ADR-004_Cryptography_Primary_Crypto_Backend.md) — Crypto backend selection.
- [ADR-007](decisions/ADR-007_Isolate_per_Connection_Architecture.md) — Isolate architecture.

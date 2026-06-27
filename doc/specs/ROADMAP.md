# Implementation Roadmap

**Version**: 1.0-draft  
**Status**: Specification  
**Subsystem**: Project Planning

---

## 1. Purpose

This document defines the phased implementation plan for `dart_quic`: from specification through reference implementation to optimization, libp2p integration, and eventual consumption by `dart_ipfs`.

---

## 2. Phases Overview

```
Phase 0: Specification           ← CURRENT PHASE
Phase 1: Core QUIC Transport
Phase 2: HTTP/3
Phase 3: WebTransport
Phase 4: libp2p Integration
Phase 5: Optimization & Hardening
Phase 6: dart_ipfs Integration
```

---

## 3. Phase 0: Specification (Current)

**Goal**: Complete, research-backed specification of all subsystems.

### Deliverables

- [x] Project charter and scope (README.md)
- [ ] Research notes (9 documents in `doc/research/`)
- [ ] Formal specifications (11 documents in `doc/specs/`)
- [ ] Architecture documents (4 documents in `doc/architecture/`)
- [ ] Internal consistency review
- [ ] External review (domain experts)

### Exit Criteria

- All spec documents exist and cross-reference each other.
- Acceptance criteria defined for every subsystem.
- No unresolved architectural questions.

---

## 4. Phase 1: Core QUIC Transport

**Goal**: RFC 9000-compliant QUIC implementation capable of establishing connections, transferring data, and recovering from loss.

### Milestones

| Milestone | Description | Dependencies |
|-----------|-------------|--------------|
| 1.1 | Wire codec (varint, headers, frames) | None |
| 1.2 | Initial secret derivation + packet protection | 1.1 |
| 1.3 | TLS 1.3 integration (handshake) | 1.2 |
| 1.4 | Connection state machine | 1.3 |
| 1.5 | Stream multiplexing + flow control | 1.4 |
| 1.6 | Loss detection + NewReno congestion | 1.5 |
| 1.7 | Connection migration | 1.6 |
| 1.8 | 0-RTT support | 1.3, 1.6 |

### Exit Criteria

- Passes QUIC Interop Runner handshake + transfer tests.
- Successfully communicates with quic-go client and server.
- All unit tests pass with > 90% coverage.

---

## 5. Phase 2: HTTP/3

**Goal**: RFC 9114-compliant HTTP/3 layer on top of QUIC.

### Milestones

| Milestone | Description | Dependencies |
|-----------|-------------|--------------|
| 2.1 | QPACK codec (static table, Huffman, integers) | Phase 1 |
| 2.2 | HTTP/3 frame parsing/serialization | 2.1 |
| 2.3 | Control stream + SETTINGS exchange | 2.2 |
| 2.4 | Request/response on bidirectional streams | 2.3 |
| 2.5 | Dynamic table (QPACK encoder/decoder streams) | 2.4 |
| 2.6 | Server push | 2.4 |
| 2.7 | GOAWAY and graceful shutdown | 2.4 |

### Exit Criteria

- Passes h3spec conformance suite.
- `Http3Client` can communicate with nginx/caddy HTTP/3 servers.
- `Http3Server` can serve requests from Chrome/curl HTTP/3 clients.

---

## 6. Phase 3: WebTransport

**Goal**: WebTransport over HTTP/3 support.

### Milestones

| Milestone | Description | Dependencies |
|-----------|-------------|--------------|
| 3.1 | Extended CONNECT mechanism | Phase 2 |
| 3.2 | QUIC Datagram frame support (RFC 9221) | Phase 1 |
| 3.3 | WebTransport session establishment | 3.1, 3.2 |
| 3.4 | Bidirectional/unidirectional WT streams | 3.3 |
| 3.5 | Datagram send/receive | 3.3 |
| 3.6 | Session lifecycle (CLOSE, DRAIN capsules) | 3.3 |
| 3.7 | Multiple sessions per connection | 3.6 |

### Exit Criteria

- `WebTransportSession` API complete and functional.
- Interop with Chromium's WebTransport implementation.
- Datagrams work end-to-end.

---

## 7. Phase 4: libp2p Integration

**Goal**: libp2p-compatible QUIC transport for the Dart libp2p stack.

### Milestones

| Milestone | Description | Dependencies |
|-----------|-------------|--------------|
| 4.1 | Multiaddr parsing (`/udp/.../quic-v1`) | None |
| 4.2 | Certificate generation with libp2p extension | Phase 1 |
| 4.3 | Custom TLS verifier (peer ID derivation) | 4.2 |
| 4.4 | ALPN "libp2p" negotiation | Phase 1 |
| 4.5 | Connection + stream integration | 4.3 |
| 4.6 | multistream-select on QUIC streams | 4.5 |
| 4.7 | NAT traversal (DCUtR coordination) | 4.5 |

### Exit Criteria

- dart_quic ↔ go-libp2p QUIC connection succeeds.
- Peer ID verification works end-to-end.
- Can run libp2p protocols (ping, identify) over the transport.

---

## 8. Phase 5: Optimization & Hardening

**Goal**: Production readiness.

### Areas

| Area | Work |
|------|------|
| Performance | Isolate-based crypto, minimize allocations, zero-copy paths |
| Congestion | CUBIC implementation, BBR exploration |
| Security | Full security audit, fuzz testing campaign |
| Resilience | Chaos testing, recovery from every error condition |
| API polish | Dartdoc, examples, changelog, semver stability |
| Packaging | pub.dev publication, CI/CD pipeline |

### Exit Criteria

- Performance benchmarks meet acceptable thresholds for client-side use.
- Zero known security vulnerabilities.
- Published on pub.dev with 1.0.0 release.
- Comprehensive documentation and examples.

---

## 9. Phase 6: dart_ipfs Integration

**Goal**: `dart_quic` consumed by `dart_ipfs` as the QUIC transport.

### Integration Points

| Component | dart_ipfs Usage |
|-----------|----------------|
| libp2p QUIC transport | Plugged into `Libp2pRouter` |
| `/quic-v1` multiaddr | Listen + dial addresses |
| TLS 1.3 (libp2p) | Peer authentication |
| Stream multiplexing | Protocol streams (Bitswap, Kademlia, etc.) |
| Connection migration | Mobile P2P resilience |

### Exit Criteria

- `dart_ipfs` can listen on `/quic-v1` addresses.
- `dart_ipfs` can dial go-ipfs and js-ipfs QUIC nodes.
- TCP fallback works when QUIC is unavailable.

---

## 10. Timeline Estimates

| Phase | Estimated Duration | Prerequisites |
|-------|-------------------|---------------|
| Phase 0 (Spec) | 2-4 weeks | None |
| Phase 1 (Core QUIC) | 8-12 weeks | Phase 0 complete |
| Phase 2 (HTTP/3) | 4-6 weeks | Phase 1 milestone 1.5+ |
| Phase 3 (WebTransport) | 3-4 weeks | Phase 2 complete |
| Phase 4 (libp2p) | 4-6 weeks | Phase 1 complete |
| Phase 5 (Optimization) | 4-8 weeks | Phases 1-4 complete |
| Phase 6 (dart_ipfs) | 2-4 weeks | Phase 4, Phase 5 |

**Total estimated**: 6-10 months from spec completion to dart_ipfs integration.

---

## 11. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Dart crypto performance insufficient | Medium | High | Isolate offloading; profile early |
| TLS 1.3 pure-Dart complexity | Medium | High | Use package:cryptography native backends |
| Interop failures with go-libp2p | Low | High | Test early and often; join libp2p interop group |
| RFC ambiguity / implementation differences | Medium | Medium | Consult errata; test against multiple impls |
| Dart SDK breaking changes | Low | Medium | Pin SDK version; track stable channel |
| Scope creep (QUIC v2, new extensions) | Medium | Low | Stick to Phase roadmap; defer extensions |

---

## 12. Acceptance Criteria (Roadmap Document)

- [ ] All phases defined with clear milestones.
- [ ] Dependencies between phases are explicit.
- [ ] Exit criteria defined for each phase.
- [ ] Risk assessment covers known concerns.
- [ ] Timeline estimates are defensible.
- [ ] Integration with dart_ipfs clearly scoped.

---

## 13. Security Considerations

- Security audit (Phase 5) is mandatory before 1.0.0 release.
- No compromise on TLS 1.3 compliance at any phase.
- Fuzz testing begins in Phase 1 and continues throughout.
- Vulnerabilities discovered at any phase are P0.

---

## References

- dart_ipfs Roadmap v2.1: P0 — QUIC transport requirement
- QUIC Interop Runner: https://interop.seemann.io/
- pub.dev publishing guide: https://dart.dev/tools/pub/publishing
- libp2p Interop Tests: https://github.com/libp2p/test-plans

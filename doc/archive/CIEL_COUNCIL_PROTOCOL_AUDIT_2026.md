# Ciel Council Protocol Completeness Audit

**Date**: 2026-06-28
**Auditors**: Council of Five (Safety, Coherence, Evolution, Capability, Efficiency)
**Scope**: RFC compliance, errata, newer extensions, and libp2p spec alignment
**Methodology**: Deep online research + parallel codebase audit via subagent swarm

---

## Executive Summary

| Area | Status | Coverage | Verdict |
|------|--------|----------|---------|
| QUIC Transport (RFC 9000) | Strong | ~90% | Production-ready core |
| TLS 1.3 (RFC 9001) | Strong | ~85% | Production-ready core |
| Recovery (RFC 9002) | Strong | ~90% | Production-ready core |
| HTTP/3 (RFC 9114) | Good | ~70% | Missing newer extensions |
| QPACK (RFC 9204) | Good | ~75% | Encoder/decoder streams missing |
| WebTransport (RFC 9220) | Good | ~70% | Spec-only for some features |
| libp2p QUIC | Partial | ~50% | TLS extension not implemented |
| **Overall** | **Good** | **~78%** | **Solid foundation, gaps in extensions** |

---

## 1. QUIC Transport (RFC 9000) — Audit Findings

### ✅ Fully Implemented (Core Protocol)

| Feature | File | Status |
|---------|------|--------|
| All 22 frame types | `lib/src/wire/frame.dart` | 100% |
| Connection ID management | `lib/src/connection/connection_id_manager.dart` | 100% |
| Version negotiation (v1 + v2) | `lib/src/connection/version_negotiation.dart` | 100% |
| PATH_CHALLENGE/PATH_RESPONSE | `lib/src/connection/migration_helper.dart` | 100% |
| 0-RTT key derivation | `lib/src/crypto/zero_rtt_helper.dart` | 100% |
| Key update | `lib/src/crypto/packet/key_update.dart` | 100% |
| Stateless reset | `lib/src/wire/stateless_reset_generator.dart` | 100% |

### ⚠️ Partially Implemented

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| Connection migration | NAT rebinding detection, preferred address, probing | Medium |
| Retry token validation | Validation logic, integrity tag verification (RFC 9001 Sec 5.8) | High |
| ECN processing | Codepoint marking, feedback integration, capability negotiation | Low |

### ❌ Missing Extensions

| RFC | Feature | Impact | Priority |
|-----|---------|--------|----------|
| **RFC 9221** | Unreliable datagrams (DATAGRAM frame, max_datagram_frame_size TP) | Cannot send UDP-like datagrams over QUIC | **HIGH** |
| **RFC 9287** | Greasing the QUIC bit (grease_quic_bit TP) | Ossification risk | Medium |
| **RFC 9368** | Compatible version negotiation (version_information TP) | Cannot negotiate compatible versions for 0-RTT | Medium |

### 🔴 Errata Requiring Action

| Erratum | Section | Issue | Status |
|---------|---------|-------|--------|
| **8240** | Table 3 | CONNECTION_CLOSE should not count toward congestion control (missing "C" marker) | **VERIFY** |
| **7861** | 8.1.2 | Invalid Retry tokens from other servers should be ignored per 8.1.3 | **REVIEW** |
| **8875** | 8.2.2 | PATH_CHALLENGE DoS vector — cross-ref to Section 21.9 | Already protected (maxPendingChallenges=8) |
| **6811** | 5.1.1 | Sequence numbering with preferred_address | Likely correct |

---

## 2. TLS 1.3 (RFC 9001) — Audit Findings

### ✅ Fully Implemented

| Feature | File | Status |
|---------|------|--------|
| Handshake state machine | `lib/src/crypto/tls/handshake_state_machine.dart` | Complete |
| ClientHello/ServerHello | `client_hello.dart`, `server_hello.dart` | Complete |
| Certificate chain parsing | `certificate_message.dart`, `certificate_verifier.dart` | Complete |
| CertificateVerify (signatures) | `certificate_verify.dart` | Complete |
| Finished message | `finished_message.dart` | Complete |
| EncryptedExtensions | `encrypted_extensions.dart` | Complete |
| X25519 key exchange | `handshake_key_exchange.dart` | Complete |
| Key derivation (Initial → Handshake → Application) | `key_manager.dart` | Complete |
| Transcript hash | `transcript_hash.dart` | Complete |

### ⚠️ Partially Implemented

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| Session resumption (PSK) | NewSessionTicket generation, PSK binder computation | Medium |
| TLS extensions | SNI, ALPN, early_data signaling, supported_groups | Medium |
| Certificate revocation | CRL/OCSP checks | Low |

---

## 3. Recovery (RFC 9002) — Audit Findings

### ✅ Fully Implemented

| Feature | File | Status |
|---------|------|--------|
| RTT estimation (smoothed, var, min, latest) | `rtt_estimator.dart` | Complete |
| Loss detection (packet + time threshold) | `loss_detector.dart` | Complete |
| PTO scheduling | `pto_scheduler.dart` | Complete |
| NewReno congestion control | `congestion_controller.dart` | Complete |
| Sent packet tracking | `sent_packet_tracker.dart` | Complete |
| Recovery coordination | `recovery_manager.dart` | Complete |
| ACK generation | `ack_generator.dart` | Complete |

### ⚠️ Partially Implemented

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| ECN integration | Codepoint marking, feedback into CC | Low |
| Pacing enforcement | Calculator exists but not enforced | Low |
| CUBIC | Explicitly deferred per ADR-002 | Future |

---

## 4. HTTP/3 (RFC 9114) — Audit Findings

### ✅ Fully Implemented

| Feature | File | Status |
|---------|------|--------|
| Core frame types (DATA, HEADERS, SETTINGS, GOAWAY, etc.) | `lib/src/http3/frame_types.dart` | Complete |
| Connection management | `http3_connection.dart` | Complete |
| Settings exchange | `settings_frame.dart` | Complete (core settings) |
| Stream discrimination | `http3_stream.dart` | Complete |

### ❌ Missing Extensions

| RFC | Feature | What's Missing | Priority |
|-----|---------|---------------|----------|
| **RFC 9220** | Extended CONNECT | SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08), `:protocol` pseudo-header | **HIGH** |
| **RFC 9297** | HTTP Datagrams | SETTINGS_H3_DATAGRAM (0x33), Capsule Protocol | **HIGH** |
| **RFC 9412** | ORIGIN frame | ORIGIN (0x0c) frame type | Medium |
| **RFC 9218** | PRIORITY_UPDATE | Frame types 0xF0700/0xF0701 | Medium |

### 🔴 Errata Requiring Action

| Erratum | Issue | Status |
|---------|-------|--------|
| **7702** | Paths starting with "//" should be allowed | **FIX** |

---

## 5. QPACK (RFC 9204) — Audit Findings

### ✅ Fully Implemented

| Feature | File | Status |
|---------|------|--------|
| Static table (99 entries) | `qpack_static_table.dart` | Complete |
| Dynamic table | `qpack_dynamic_table.dart` | Complete |
| Encoder/Decoder (basic) | `qpack_encoder.dart`, `qpack_decoder.dart` | Complete |
| Integer/string encoding | `qpack_integer.dart`, `qpack_string.dart` | Complete |

### ❌ Missing

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| Encoder/decoder streams | Insert/duplicate/set capacity instructions; ack/cancel/increment | **HIGH** |
| Huffman encoding | String literal Huffman coding | Low |

### 🔴 Errata Requiring Action

| Erratum | Issue | Status |
|---------|-------|--------|
| **8410** | `requiredInsertCount = max(requiredInsertCount, dynamicIndex + 1)` | **VERIFY** |
| **7277** | Static table entries 73/74 values | Already correct |

---

## 6. WebTransport (RFC 9220 / draft-ietf-webtrans-http3-15) — Audit Findings

### ✅ Fully Implemented

| Feature | File | Status |
|---------|------|--------|
| Capsule types | `capsule_types.dart` | Complete |
| Session management | `webtransport_session.dart` | Complete |
| Stream type discrimination | `stream_types.dart` | Complete |
| Datagram capsules | `datagram_capsule.dart` | Complete |

### ❌ Missing

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| Session establishment | Extended CONNECT request/response, `:protocol = webtransport` | **HIGH** |
| HTTP/3 SETTINGS integration | SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_H3_DATAGRAM | **HIGH** |
| Draft version negotiation | SETTINGS_WT_ENABLED codepoint per draft version | Medium |
| Stream dispatch by session ID | Multi-session routing | Medium |

---

## 7. libp2p QUIC Transport — Audit Findings

### ✅ Implemented

| Feature | File | Status |
|---------|------|--------|
| Multiaddr parsing | `multiaddr.dart` | Complete |
| Peer ID handling | `peer_id.dart` | Complete |
| DCUtR message format | `dcutr.dart` | Complete |
| DCUtR state machine | `dcutr_state_machine.dart` | Complete |
| Transport dial/listen APIs | `libp2p_quic_transport.dart` | Complete |

### ❌ Critical Missing Pieces

| Feature | What's Missing | Priority |
|---------|---------------|----------|
| **libp2p TLS extension** | X.509 extension (OID 1.3.6.1.4.1.53594.1.1), SignedKey protobuf | **CRITICAL** |
| **ALPN "libp2p"** | ALPN negotiation in TLS handshake | **CRITICAL** |
| **Peer ID verification** | Extract/verify peer ID from certificate extension | **CRITICAL** |
| **Multistream-select** | Protocol negotiation per stream | High |
| **Relay integration** | DCUtR requires relay connection | Medium |

**Without the libp2p TLS extension, quic_lib cannot authenticate libp2p peers.** This is the single biggest gap in the entire codebase.

---

## 8. Complete RFC Reference Table

| RFC | Title | Status in quic_lib |
|-----|-------|-------------------|
| RFC 8999 | Version-Independent Properties of QUIC | Referenced |
| RFC 9000 | QUIC Transport Protocol | ~90% implemented |
| RFC 9001 | Using TLS to Secure QUIC | ~85% implemented |
| RFC 9002 | QUIC Loss Detection and Congestion Control | ~90% implemented |
| **RFC 9114** | **HTTP/3** | **~70% implemented** |
| **RFC 9204** | **QPACK** | **~75% implemented** |
| **RFC 9220** | **Bootstrapping WebSockets with HTTP/3** | **Not implemented** |
| **RFC 9221** | **Unreliable Datagram Extension to QUIC** | **Not implemented** |
| RFC 9287 | Greasing the QUIC Bit | Not implemented |
| RFC 9297 | HTTP Datagrams and the Capsule Protocol | Not implemented |
| RFC 9298 | Proxying UDP in HTTP/3 | Not implemented |
| RFC 9308 | Applicability of the QUIC Transport Protocol | Referenced |
| RFC 9312 | Manageability of the QUIC Transport Protocol | Referenced |
| **RFC 9368** | **Compatible Version Negotiation for QUIC** | **Partial** |
| RFC 9369 | QUIC Version 2 | Implemented |
| **RFC 9412** | **The ORIGIN Extension in HTTP/3** | **Not implemented** |
| draft-ietf-webtrans-http3-15 | WebTransport over HTTP/3 | Partial |
| draft-ietf-quic-multipath-21 | Multipath QUIC | Not started |

---

## 9. Ciel Council Recommendations

### Phase 1: Critical Fixes (Immediate — 1-2 weeks)

1. **Verify CONNECTION_CLOSE congestion control exclusion** (Errata 8240)
2. **Review retry token validation** (Errata 7861)
3. **Verify QPACK encoder `requiredInsertCount`** (Errata 8410)
4. **Fix HTTP/3 path validation for "//" prefix** (Errata 7702)

### Phase 2: High-Priority Features (2-4 weeks)

5. **Implement RFC 9221 DATAGRAM frames** — Required for WebTransport datagrams and any UDP-like QUIC usage
6. **Add Extended CONNECT support** (RFC 9220) — SETTINGS_ENABLE_CONNECT_PROTOCOL + `:protocol` pseudo-header
7. **Add HTTP Datagrams** (RFC 9297) — SETTINGS_H3_DATAGRAM + Capsule Protocol
8. **Implement libp2p TLS extension** — OID 1.3.6.1.4.1.53594.1.1 + SignedKey protobuf + ALPN "libp2p"

### Phase 3: Medium-Priority Features (4-8 weeks)

9. **QPACK encoder/decoder streams** — Required for correct dynamic table operation
10. **ORIGIN frame** (RFC 9412) — Connection coalescing
11. **PRIORITY_UPDATE frame** (RFC 9218) — Prioritization
12. **RFC 9287 greasing** — QUIC bit randomization for ossification resistance
13. **RFC 9368 compatible version negotiation** — version_information transport parameter

### Phase 4: Long-Term (Future releases)

14. **Multipath QUIC** (draft-ietf-quic-multipath-21) — IESG submission pending
15. **CUBIC congestion control** — Performance optimization per ADR-002
16. **Huffman encoding** — QPACK optimization
17. **WebSockets over HTTP/3** (RFC 9220) — Separate from WebTransport
18. **Multistream-select** — libp2p protocol negotiation

---

## 10. Security Considerations

### Already Protected
- PATH_CHALLENGE DoS (maxPendingChallenges=8)
- Anti-amplification limit
- RTT and ACK delay capping
- Per-IP datagram rate limiting
- Memory exhaustion bounds (max packets, max CIDs, max tickets)

### Needs Attention
- Retry token validation per Errata 7861
- CONNECTION_CLOSE congestion control exclusion per Errata 8240
- libp2p peer authentication (TLS extension gap is a security issue)

---

*Audit completed by the Ciel Council of Five. Recommendations prioritized by Safety, Coherence, Evolution, Capability, and Efficiency.*

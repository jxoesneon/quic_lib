# Documentation Index

**dart_quic** — Pure-Dart QUIC/HTTP3/WebTransport/libp2p specification

---

## Reading Order

For newcomers, start with Architecture → Research → Specs:

1. [Module Overview](architecture/MODULE_OVERVIEW.md) — system layering and module catalog
2. [RFC 9000 Notes](research/RFC_9000_NOTES.md) — QUIC core transport concepts
3. [QUIC Wire Spec](specs/QUIC_WIRE_SPEC.md) — packet encoding (foundation)
4. [QUIC Crypto Spec](specs/QUIC_CRYPTO_SPEC.md) — TLS 1.3 + packet protection
5. [QUIC Streams Spec](specs/QUIC_STREAMS_SPEC.md) — multiplexing + flow control
6. [Data Flow](architecture/DATA_FLOW.md) — receive/send processing pipelines
7. Then HTTP/3, WebTransport, libp2p in any order

---

## Research (`research/`)

Deep RFC analysis and prior-art survey.

| Document | Topic | Primary Source |
|----------|-------|---------------|
| [RFC_9000_NOTES.md](research/RFC_9000_NOTES.md) | QUIC core transport | RFC 9000 |
| [RFC_9001_NOTES.md](research/RFC_9001_NOTES.md) | TLS 1.3 over QUIC | RFC 9001 |
| [RFC_9002_NOTES.md](research/RFC_9002_NOTES.md) | Loss detection & recovery | RFC 9002 |
| [RFC_9114_NOTES.md](research/RFC_9114_NOTES.md) | HTTP/3 | RFC 9114 |
| [RFC_9204_NOTES.md](research/RFC_9204_NOTES.md) | QPACK header compression | RFC 9204 |
| [WEBTRANSPORT_DRAFT_NOTES.md](research/WEBTRANSPORT_DRAFT_NOTES.md) | WebTransport over HTTP/3 | draft-ietf-webtrans-http3 |
| [LIBP2P_QUIC_SPEC_NOTES.md](research/LIBP2P_QUIC_SPEC_NOTES.md) | libp2p QUIC transport | libp2p specs |
| [PRIOR_ART_ANALYSIS.md](research/PRIOR_ART_ANALYSIS.md) | 9 existing QUIC implementations | Multiple |
| [DART_ECOSYSTEM_GAP.md](research/DART_ECOSYSTEM_GAP.md) | Why Dart needs pure QUIC | Ecosystem survey |

---

## Specifications (`specs/`)

Formal implementation blueprints with acceptance criteria.

| Document | Subsystem | RFC Basis |
|----------|-----------|-----------|
| [QUIC_WIRE_SPEC.md](specs/QUIC_WIRE_SPEC.md) | Wire encoding (varint, headers, frames) | RFC 9000 §12, 16, 17, 19 |
| [QUIC_CRYPTO_SPEC.md](specs/QUIC_CRYPTO_SPEC.md) | TLS 1.3, AEAD, header protection, key update | RFC 9001, RFC 8446 |
| [QUIC_STREAMS_SPEC.md](specs/QUIC_STREAMS_SPEC.md) | Stream IDs, state machines, flow control | RFC 9000 §2-4 |
| [QUIC_RECOVERY_SPEC.md](specs/QUIC_RECOVERY_SPEC.md) | Loss detection, RTT, PTO, NewReno | RFC 9002 |
| [HTTP3_SPEC.md](specs/HTTP3_SPEC.md) | HTTP/3 stream mapping, QPACK, lifecycle | RFC 9114 |
| [WEBTRANSPORT_SPEC.md](specs/WEBTRANSPORT_SPEC.md) | Sessions, datagrams, WT streams | draft-ietf-webtrans-http3 |
| [LIBP2P_QUIC_SPEC.md](specs/LIBP2P_QUIC_SPEC.md) | Peer auth, multiaddr, ALPN | libp2p-tls, libp2p-quic |
| [DART_API_SPEC.md](specs/DART_API_SPEC.md) | Public API surface (zero-FFI) | — |
| [TESTING_SPEC.md](specs/TESTING_SPEC.md) | Conformance, interop, fuzz, CI | — |
| [SECURITY_SPEC.md](specs/SECURITY_SPEC.md) | Threat model, TLS, DoS, replay | RFC 9000 §21, RFC 9001 §9 |
| [ROADMAP.md](specs/ROADMAP.md) | 6-phase implementation plan | — |

---

## Architecture (`architecture/`)

Module design and implementation strategy.

| Document | Focus |
|----------|-------|
| [MODULE_OVERVIEW.md](architecture/MODULE_OVERVIEW.md) | Layer diagram, module catalog, dependency rules |
| [DATA_FLOW.md](architecture/DATA_FLOW.md) | Receive/send paths, stream demux, ACK processing |
| [API_SURFACE.md](architecture/API_SURFACE.md) | Class hierarchy, usage examples |
| [ROADMAP_ARCHITECTURE.md](architecture/ROADMAP_ARCHITECTURE.md) | Build order, milestone dependencies, integration points |

---

## Future Extensions (Not Yet Specified)

- QUIC Version 2 (RFC 9369)
- QUIC Datagrams standalone (RFC 9221) — currently covered within WebTransport spec
- Multipath QUIC (draft-ietf-quic-multipath)
- QUIC-LB (draft-ietf-quic-load-balancers)

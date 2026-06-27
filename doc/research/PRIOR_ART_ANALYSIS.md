---
title: "Prior Art Analysis: Existing QUIC Implementations"
category: research
companion_rfcs: []
---

# Prior Art Analysis: Existing QUIC Implementations


## 1. Purpose

Reinventing QUIC from scratch without studying existing implementations is a recipe for rediscovering known pitfalls. By analyzing quic-go, aioquic, ngtcp2, MsQuic, and others, dart_quic can adopt proven patterns-event-driven engines, pluggable congestion control, zero-copy paths-and avoid mistakes already made in C, Go, and Rust.

## 2. Overview

This document surveys major QUIC implementations across languages and evaluates their architecture, maturity, and lessons for a pure-Dart implementation.

---


## 3. Implementation Matrix

| Implementation | Language | License | RFC Version | HTTP/3 | WebTransport | Stream Scheduling | Maturity |
|---------------|----------|---------|-------------|--------|--------------|-------------------|----------|
| **quic-go** | Go | MIT | RFC 9000 | Yes | Yes | Round-Robin | Production |
| **aioquic** | Python | BSD-3 | RFC 9000 | Yes | Yes | Sequential | Production |
| **picoquic** | C | BSD-2 | RFC 9000 (partial) | Yes | No | Sequential | Research/Ref |
| **MsQuic** | C | MIT | RFC 9000 | Via HTTP.sys | No | Custom | Production |
| **ngtcp2** | C | MIT | RFC 9000 | Via nghttp3 | No | Sequential | Production |
| **Chromium QUIC** | C++ | BSD-3 | RFC 9000 | Yes | Yes | Priority-based | Production |
| **quiche** (Cloudflare) | Rust | BSD-2 | RFC 9000 | Yes | No | Custom | Production |
| **quinn** | Rust | MIT/Apache-2 | RFC 9000 | Via h3 crate | No | Custom | Production |
| **pure_dart_quic** | Dart | — | RFC 9000 | Basic | Basic | N/A | Experimental |

---


## 4. Detailed Analysis

### 1. quic-go (Go)

**Repository**: https://github.com/quic-go/quic-go  
**Stars**: ~10k | **Active**: Yes

**Architecture**:
- Single-threaded per connection (Go goroutines).
- Clean separation: `internal/` for wire format, `quic/` for public API.
- QPACK implementation in a separate `qpack` package.
- Supports HTTP/3 via `http3` package.
- WebTransport support built atop HTTP/3.

**Key Design Decisions**:
- Uses Go's `net.PacketConn` for UDP I/O.
- Congestion control abstracted behind an interface (supports NewReno, CUBIC).
- TLS via Go's `crypto/tls` (modified fork for QUIC-specific APIs).
- Connection migration supported.

**Lessons for Dart**:
- Clean public API: `quic.Dial()`, `quic.Listen()`, `quic.Stream` — minimal surface.
- Goroutine-per-stream model maps well to Dart's async/await + isolates.
- Separate HTTP/3 from QUIC core.

---

### 2. aioquic (Python)

**Repository**: https://github.com/aiortc/aioquic  
**Stars**: ~2k | **Active**: Yes

**Architecture**:
- Built on Python asyncio.
- Core protocol engine in pure Python; crypto via `cryptography` library.
- Separation: `quic/` (transport), `h3/` (HTTP/3), `tls/` (handshake).
- Event-driven: protocol emits events, application handles them.

**Key Design Decisions**:
- Event/callback model: `QuicConnection.receive_datagram()` → events.
- No threads; single event loop (like Dart's event loop).
- TLS 1.3 implementation included (not using OpenSSL for TLS records — only for crypto primitives).
- Used as the reference implementation for QUIC interop testing.

**Lessons for Dart**:
- Pure-language TLS is feasible (aioquic does TLS in Python with C crypto backend).
- Event-driven architecture maps perfectly to Dart Streams.
- Being a reference impl for interop is valuable for testing.
- Performance is secondary to correctness in the spec stage.

---

### 3. picoquic (C)

**Repository**: https://github.com/nicoquic/picoquic  
**Stars**: ~500 | **Active**: Yes

**Architecture**:
- Single C library; minimal dependencies (picotls for TLS).
- Designed as a test and experimentation platform.
- Clean state machine design.

**Key Design Decisions**:
- Callback-based API.
- Integrated congestion control experiments (BBR, CUBIC, NewReno).
- Extensive logging for protocol analysis.
- Used in QUIC interop runner.

**Lessons for Dart**:
- State machine approach for connection/stream lifecycle is clean and testable.
- Extensive logging from day one aids debugging.
- Interop test compatibility should be a goal.

---

### 4. MsQuic (C)

**Repository**: https://github.com/microsoft/msquic  
**Stars**: ~4k | **Active**: Yes (Microsoft)

**Architecture**:
- Cross-platform (Windows, Linux, macOS).
- Highly optimized for Windows kernel integration.
- Async I/O model.
- Used by Windows HTTP stack, .NET, and Edge.

**Key Design Decisions**:
- Platform-specific optimizations (Windows kernel bypass, io_uring on Linux).
- Schannel (Windows) or OpenSSL (Linux) for TLS.
- Connection pooling and load balancing built in.
- Designed for high-throughput server scenarios.

**Lessons for Dart**:
- Platform-specific optimizations are out of scope for pure Dart.
- Connection pooling and load balancing are important for production use.
- Demonstrates that QUIC can serve as a general-purpose transport (not just HTTP/3).

---

### 5. ngtcp2 (C)

**Repository**: https://github.com/ngtcp2/ngtcp2  
**Stars**: ~1k | **Active**: Yes

**Architecture**:
- Library-only (no I/O — user provides send/recv callbacks).
- Crypto backend abstracted (supports OpenSSL, GnuTLS, wolfSSL, boringSSL).
- HTTP/3 via separate `nghttp3` library.

**Key Design Decisions**:
- Zero-copy design philosophy.
- No I/O opinions — pure protocol engine.
- Excellent separation of concerns.

**Lessons for Dart**:
- Separating I/O from protocol logic is excellent architecture.
- A pure protocol engine can be tested without a network.
- Crypto backend abstraction allows flexibility.

---

### 6. Chromium QUIC (C++)

**Architecture**:
- Deeply integrated into Chromium network stack.
- Priority-based stream scheduling (mirrors HTTP/2 priority tree).
- WebTransport native support.
- BBRv2 congestion control.

**Lessons for Dart**:
- Real-world browser requirements drive features (WebTransport, priority, 0-RTT).
- Demonstrates the full stack from QUIC to WebTransport.
- Too tightly coupled to Chromium to serve as a reference — but useful for correctness comparison.

---

### 7. pure_dart_quic (Dart)

**Repository**: https://github.com/KellyKinyama/pure-dart-quic  
**Published**: pub.dev (0.x)

**Architecture**:
- Single package; includes QUIC, TLS 1.3, HTTP/3, WebTransport.
- Uses `RawDatagramSocket` for UDP I/O.
- Initial secret derivation, packet protection, CRYPTO frame exchange.
- Basic QPACK and HTTP/3 settings.

**Key Observations**:
- Proves feasibility of pure-Dart QUIC.
- Demonstrates `RawDatagramSocket` usage pattern.
- Appears to be a proof-of-concept; not production-ready.
- Missing: congestion control, connection migration, full stream lifecycle, comprehensive error handling.

**Lessons for dart_quic**:
- `RawDatagramSocket` is the correct Dart API for UDP.
- TLS 1.3 in pure Dart is achievable (with crypto primitives from a native-backed library).
- The primary challenge is completeness and correctness, not feasibility.

---


## 5. Architectural Patterns Across Implementations

### Common Layering

```
┌──────────────────┐
│  Application     │  (HTTP/3, WebTransport, libp2p)
├──────────────────┤
│  Stream Manager  │  (multiplex, flow control, scheduling)
├──────────────────┤
│  Loss & CC       │  (detection, recovery, congestion)
├──────────────────┤
│  Packet I/O      │  (encryption, decryption, framing)
├──────────────────┤
│  TLS Engine      │  (handshake, key derivation)
├──────────────────┤
│  UDP Socket      │  (send/receive datagrams)
└──────────────────┘
```

### Common Design Choices

1. **Separate crypto from protocol**: All mature implementations abstract the crypto backend.
2. **Event-driven or callback-based**: Matches Dart's async model well.
3. **Per-connection state machine**: Explicit states for handshake, established, closing, closed.
4. **Pluggable congestion control**: Interface-based; swap NewReno for CUBIC or BBR.
5. **Separate packet number spaces**: Tracked independently per encryption level.

---


## 6. Performance Benchmarks (from research literature)

| Sender → Receiver | Throughput (Gbit/s) |
|-------------------|---------------------|
| ngtcp2 → ngtcp2 | 4.17 |
| quiche → quiche | 2.97 |
| quic-go → quic-go | 1.32 |
| lsquic → lsquic | 2.47 |
| picoquic → picoquic | 2.23 |

(Source: TUM NET-2022-07 study, controlled environment)

Note: Dart's single-threaded event loop may limit raw throughput compared to C/Rust implementations, but for most application scenarios (especially P2P and client use), this is acceptable.

---


## 7. Conclusions for dart_quic Design

1. **Follow ngtcp2/aioquic pattern**: Separate protocol engine from I/O.
2. **Use Dart Streams/Futures natively**: Don't fight the language's async model.
3. **Prioritize correctness**: Use interop test suites (QUIC interop runner).
4. **Layer cleanly**: QUIC core → HTTP/3 → WebTransport → libp2p adapter.
5. **Abstract crypto**: Allow multiple backends (package:cryptography, pointycastle, future dart:crypto).
6. **Start with NewReno**: Simple, well-understood; add CUBIC/BBR later.

---


## 8. References

- QUIC Implementations Wiki: https://github.com/quicwg/base-drafts/wiki/Implementations
- QUIC Interop Runner: https://interop.seemann.io/
- TUM Performance Study: https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2022-07-1/NET-2022-07-1_10.pdf
- pure_dart_quic: https://pub.dev/packages/pure_dart_quic
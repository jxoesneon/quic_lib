# Dart Ecosystem Gap Analysis: Why Pure Dart Needs a QUIC Stack

---

## The Problem

As of mid-2026, the Dart ecosystem has **no production-ready, pure-Dart QUIC implementation**. This gap blocks:

1. **dart_ipfs**: Requires QUIC transport for libp2p (`/udp/.../quic-v1` multiaddr support).
2. **HTTP/3 adoption**: Dart servers and clients cannot natively speak HTTP/3.
3. **WebTransport**: Real-time web applications in Dart cannot use the WebTransport API.
4. **Edge/IoT**: Pure-Dart is essential for platforms where native FFI is unavailable or impractical (e.g., Dart Native on embedded, WASM compilation targets).

---

## Current Landscape

### Official Dart SDK Position

- **dart:io**: Provides `RawDatagramSocket` for UDP, `SecureSocket` for TLS over TCP. No QUIC primitives.
- **GitHub Issue #38595** (dart-lang/sdk): "Add HTTP/3 support" — open since 2019. The Dart team's position: HTTP/3 should be a community-contributed package, not core SDK.
- **package:http**: TCP-only; no QUIC path.
- **Cronet integration** (package:cronet_http): Wraps Google's Chromium network stack via FFI. Supports QUIC/HTTP/3 but is **not pure Dart** and is mobile-only.

### Existing Dart Packages

| Package | Approach | QUIC | HTTP/3 | Pure Dart | Production |
|---------|----------|------|--------|-----------|------------|
| `cronet_http` | FFI to Chromium Cronet | Yes | Yes | No (native) | Mobile only |
| `pure_dart_quic` | Pure Dart | Partial | Basic | Yes | No (PoC) |
| `dart_quic` (this project) | Pure Dart | Planned | Planned | Yes | Spec stage |

### Gap Summary

| Requirement | Available? | Notes |
|-------------|-----------|-------|
| QUIC transport (RFC 9000) | No (pure Dart) | `pure_dart_quic` is PoC only |
| TLS 1.3 over QUIC (RFC 9001) | No | No pure-Dart QUIC-TLS integration |
| HTTP/3 (RFC 9114) | No (pure Dart) | Only via Cronet FFI |
| WebTransport | No | No implementation at all |
| libp2p QUIC | No | No `/quic-v1` transport in Dart libp2p |
| Congestion control | No | No pure-Dart implementation |
| Connection migration | No | Not implemented anywhere in Dart |

---

## Constraints Unique to Dart

### 1. Single-Threaded Event Loop

Dart's concurrency model is a single-threaded event loop with isolates for parallelism. This means:
- **No shared mutable state between isolates** (message-passing only).
- **Non-blocking I/O is natural** (`async`/`await`, `Stream`).
- **CPU-intensive crypto must be offloaded** to isolates or native extensions.
- **Timer granularity** is limited by the event loop (microtask queue).

**Implication**: The QUIC implementation must be async-native. Crypto operations (AES-GCM, ChaCha20) that process many packets per second may need isolate offloading.

### 2. No Raw Socket Access (Beyond UDP)

- `RawDatagramSocket` provides UDP send/recv.
- No kernel bypass (no io_uring, no DPDK).
- No `sendmmsg`/`recvmmsg` (batch send/recv) — each datagram is a separate operation.
- GSO (Generic Segmentation Offload) unavailable.

**Implication**: Throughput ceiling is lower than C/Rust implementations. Acceptable for client-side and P2P use; may limit high-throughput server scenarios.

### 3. Crypto Availability

| Operation | Pure Dart | Native-Backed (package:cryptography) |
|-----------|-----------|--------------------------------------|
| AES-128-GCM | package:pointycastle (slow) | Yes (hardware-accelerated) |
| AES-256-GCM | package:pointycastle (slow) | Yes |
| ChaCha20-Poly1305 | package:pointycastle | Yes |
| HKDF-SHA256 | Yes | Yes |
| X25519 (key exchange) | Yes | Yes |
| Ed25519 (signing) | Yes | Yes |
| SHA-256 | Yes | Yes |

**Implication**: `package:cryptography` should be the primary crypto backend (uses platform-native implementations where available). Fallback to `package:pointycastle` for WASM or restricted environments.

### 4. No dart:ffi on All Targets

- dart:ffi works on native platforms (Linux, macOS, Windows, Android, iOS).
- NOT available on web (dart2js, dart2wasm).
- NOT reliably available on all embedded targets.

**Implication**: The core QUIC implementation must be pure Dart. Native crypto acceleration is an optimization, not a requirement.

### 5. WASM Compilation Target

Dart is increasingly targeting WASM (via `dart2wasm`). Constraints:
- No file system access.
- No raw UDP sockets (must use browser APIs or WASM networking proposals).
- Crypto via WebCrypto API.

**Implication**: WASM support is a future goal. The architecture should not preclude it, but the initial implementation targets `dart:io` (native) platforms.

---

## Why Build This Now

### 1. dart_ipfs P0 Dependency

The `dart_ipfs` project requires QUIC transport as its P0 priority. Without it, the Dart libp2p implementation cannot participate in the standard IPFS network using QUIC multiaddrs.

### 2. HTTP/3 is Becoming the Default

Major CDNs and services are defaulting to HTTP/3. Dart servers that cannot speak HTTP/3 face:
- Higher latency (TCP handshake overhead).
- No 0-RTT.
- Head-of-line blocking.
- Inability to serve modern web clients optimally.

### 3. WebTransport for Real-Time Apps

Gaming, live collaboration, and streaming applications in Dart (Flutter) need WebTransport's unreliable datagrams and independent streams. The only alternative today is WebSocket, which has head-of-line blocking.

### 4. Ecosystem Gap = Opportunity

The Dart ecosystem is mature in many areas (HTTP clients, gRPC, protobuf) but has a glaring gap in modern transport protocols. Filling this gap positions `dart_quic` as foundational infrastructure.

---

## Design Principles Derived from Constraints

1. **Pure Dart core**: No FFI dependencies in the transport layer.
2. **Async-native**: Build on `Stream`/`Future`/`Completer` — no blocking anywhere.
3. **Crypto abstraction**: Interface for crypto operations; default to `package:cryptography`.
4. **Layered architecture**: QUIC core independent of HTTP/3, WebTransport, libp2p.
5. **Correctness first**: RFC conformance and interoperability over raw performance.
6. **Testable without network**: Protocol engine should be testable with mock I/O.
7. **Idiomatic Dart API**: Follow `dart:io` conventions (`bind`, `connect`, `Stream<List<int>>`).

---

## References

- dart-lang/sdk#38595: https://github.com/dart-lang/sdk/issues/38595
- Dart RawDatagramSocket: https://api.dart.dev/stable/dart-io/RawDatagramSocket-class.html
- package:cryptography: https://pub.dev/packages/cryptography
- package:pointycastle: https://pub.dev/packages/pointycastle
- Cronet for Dart: https://pub.dev/packages/cronet_http
- pure_dart_quic: https://pub.dev/packages/pure_dart_quic

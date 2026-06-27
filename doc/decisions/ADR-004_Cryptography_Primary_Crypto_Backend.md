---
title: "ADR-004: package:cryptography as Primary Crypto Backend"
category: decision
status: "Accepted"
---

# ADR-004: package:cryptography as Primary Crypto Backend

## 1. Purpose

Crypto is the performance bottleneck of any QUIC implementation, yet Dart ecosystem lacks a single package that is both fast everywhere and pure-Dart everywhere. Selecting package:cryptography as the default-with package:pointycastle as a fallback-gives dart_quic hardware acceleration on native platforms and web crypto on browsers, while preserving a zero-FFI core.

## 2. Detailed Specification
### 2.1 Context

Multiple Dart crypto packages exist: `package:cryptography`, `package:pointycastle`, `package:crypto`, and hand-rolled primitives. Each has different API styles, platform coverage, and performance characteristics.


### 2.2 Decision

Use `package:cryptography` as the primary crypto backend with `package:pointycastle` as a supported fallback backend. A `CryptoBackend` abstraction allows runtime or compile-time selection.


### 2.3 Consequences

- **API quality**: `package:cryptography` provides high-level, async, idiomatic Dart APIs (`SecretKey`, `Cipher`, `SignatureAlgorithm`) that reduce complexity in the TLS state machine.
- **Native acceleration**: On native platforms and the web, `package:cryptography` delegates to OS or Web Crypto APIs for AES-GCM and ChaCha20-Poly1305, yielding near-native performance without FFI.
- **Fallback coverage**: `package:pointycastle` ensures the stack still runs in environments where `package:cryptography` cannot reach platform APIs (e.g., some WASM targets).
- **Abstraction cost**: Every crypto operation goes through an interface indirection. In practice this is negligible compared to the cost of the primitive itself.
- **X.509 gap**: Neither package provides X.509 parsing; `package:x509` is required for certificate handling.
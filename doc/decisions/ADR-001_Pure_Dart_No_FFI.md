---
title: "ADR-001: Pure Dart — No FFI Dependencies"
category: decision
status: "Accepted"
---

# ADR-001: Pure Dart — No FFI Dependencies

## 1. Purpose

Wrapping a native QUIC library via dart:ffi would ship faster, but it would sacrifice the web, WASM, and embedded targets that make Dart attractive. This decision commits dart_quic to a pure-Dart core, accepting the performance tradeoff in exchange for universal portability and full maintenance control.

## 2. Detailed Specification
### 2.1 Context

Dart provides `dart:ffi` for binding to native C libraries, and many QUIC implementations (quiche, msquic, ngtcp2) are written in C/C++/Rust. Using FFI would let us wrap a mature native implementation and ship quickly.


### 2.2 Decision

Build `dart_quic` as a pure Dart implementation with zero `dart:ffi` dependencies in the core library.


### 2.3 Consequences

- **Portability**: Runs on every platform Dart supports (native, web, WASM) without platform-specific build steps or native toolchains.
- **Performance**: Pure Dart is slower than native code for crypto and packet processing. We accept this tradeoff and mitigate with pluggable crypto backends (`package:cryptography`) and isolate-based parallelism.
- **Build simplicity**: No `CMake`, `podspec`, or native binding configuration. Consumers add a pub dependency and go.
- **Maintenance control**: We own the full stack—no upstream native library releases blocking us, no ABI compatibility issues across Dart SDK versions.
- **Security audit surface**: Larger than a thin FFI wrapper, but smaller than maintaining custom native patches.
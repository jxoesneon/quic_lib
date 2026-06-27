---
title: "ADR-001: Pure Dart — No FFI Dependencies"
category: decision
status: "Accepted"
---

# ADR-001: Pure Dart — No FFI Dependencies

## 1. Purpose

Wrapping a native QUIC library via dart:ffi would ship faster, but it would limit support for web, WASM, and embedded targets where FFI is unavailable. This decision commits dart_quic to a pure-Dart core, accepting the performance tradeoff in exchange for broader portability and control over maintenance timelines.

## 2. Detailed Specification
### 2.1 Context

Dart provides `dart:ffi` for binding to native C libraries, and many QUIC implementations (quiche, msquic, ngtcp2) are written in C/C++/Rust. Using FFI would let us wrap a mature native implementation and ship quickly.


### 2.2 Decision

Build `dart_quic` as a pure Dart implementation with zero `dart:ffi` dependencies in the core library.


### 2.3 Consequences

- **Portability**: Runs on every platform Dart supports (native, web, WASM) without platform-specific build steps or native toolchains.
- **Performance**: Pure Dart is slower than native code for crypto and packet processing. We accept this tradeoff and mitigate with pluggable crypto backends (`package:cryptography`) and isolate-based parallelism.
- **Build simplicity**: No `CMake`, `podspec`, or native binding configuration. Consumers add a pub dependency and go.
- **Maintenance control**: The project maintains the full Dart layer, so upstream native library releases and ABI compatibility issues do not block development.
- **Security audit surface**: Larger than a thin FFI wrapper, but smaller than maintaining custom native patches.
---
title: "ADR-002: NewReno Before CUBIC"
category: decision
status: "Accepted"
---

# ADR-002: NewReno Before CUBIC

## 1. Purpose

Congestion control is easy to get wrong and hard to debug. Starting with NewReno-a simple, well-documented algorithm-gives dart_quic a conservative, interoperable baseline. CUBIC and BBR can be added later via the pluggable CongestionController interface once the recovery subsystem is proven correct.

## 2. Detailed Specification
### 2.1 Context

Modern QUIC and TCP stacks often adopt CUBIC or BBR as the default congestion controller because they perform better on high-BDP networks. BBR in particular requires accurate bottleneck-bandwidth and RTT estimation.


### 2.2 Decision

Implement NewReno as the default congestion controller first. CUBIC will follow in Phase 5 (Optimization & Hardening). BBR remains a future exploration item.


### 2.3 Consequences

- **Simplicity**: NewReno is well understood, easy to reason about, and quick to implement correctly.
- **RFC compliance**: RFC 9002 (QUIC Loss Detection and Congestion Control) explicitly describes NewReno behavior, giving us a direct specification to target.
- **Interop baseline**: A correct NewReno implementation interoperates reliably with all other QUIC stacks; it is the conservative, safe default.
- **Performance tradeoff**: NewReno underutilizes long-fat networks compared to CUBIC or BBR. Users will not get maximum throughput until CUBIC lands.
- **Clear upgrade path**: The recovery subsystem is designed with a pluggable `CongestionController` interface so CUBIC can slot in later without rewriting loss detection.
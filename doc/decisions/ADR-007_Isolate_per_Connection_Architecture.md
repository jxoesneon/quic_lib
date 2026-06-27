---
title: "ADR-007: Isolate-per-Connection Architecture"
category: decision
status: "Accepted"
---

# ADR-007: Isolate-per-Connection Architecture

## 1. Purpose

A single Dart event loop may struggle with concurrent crypto and packet processing for many peers. Isolates provide parallelism, and QUIC connections are naturally independent. Running each connection in its own isolate keeps one peer's heavy crypto from stalling another, which is expected to help a libp2p node that may maintain 50+ connections.

## 2. Detailed Specification
### 2.1 Context

Dart isolates provide true parallelism without shared mutable state. QUIC connections are naturally independent: each has its own connection ID, state machine, crypto keys, and stream set.


### 2.2 Decision

Run each QUIC connection inside its own Dart isolate. The main isolate owns the UDP socket and dispatches incoming packets to connection isolates via `SendPort`/`ReceivePort`. Outgoing packets are sent back to the main isolate for transmission.


### 2.3 Consequences

- **Parallelism**: Crypto, packet processing, and stream scheduling for one connection do not block another. This is critical for multi-peer libp2p nodes.
- **Memory isolation**: A misbehaving or compromised connection cannot directly corrupt another connection's state.
- **Messaging overhead**: Every packet send/receive crosses an isolate boundary, requiring serialization and port communication. We mitigate by batching packets and using typed data (`Uint8List`) where possible.
- **Complexity**: Connection lifecycle (spawn, kill, error propagation) must be managed carefully. The main isolate acts as a supervisor with a connection registry.
- **Resource limits**: Each isolate consumes memory. For high-connection-count servers, a connection pool or worker-isolate model may be needed later.
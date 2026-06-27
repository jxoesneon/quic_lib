---
title: "DART-IPFS Integration Contract"
category: architecture
version: "1.0-draft"
status: "Draft"
subsystem: "Integration Contract"
---

# DART-IPFS Integration Contract

## 1. Purpose

dart_ipfs is the primary downstream consumer of dart_quic, yet a generic QUIC library cannot guess the exact shapes its consumer needs. This integration contract defines the four-class API surface-transport, connection, stream, and peer ID-that dart_ipfs requires, ensuring that dart_quic ships with a ready-made libp2p adapter rather than forcing consumers to bridge the gap themselves.

## 2. Detailed Specification
### 2.1 Consumer: `dart_ipfs`

`dart_ipfs` needs:

- **Peer discovery** — authenticated peers that connect to the local node must be exposed.
- **Authenticated connections** — every connection is bound to a verified `PeerId` via the libp2p TLS 1.3 handshake.
- **Bidirectional streams** — outbound and inbound streams on a single QUIC connection.
- **Connection multiplexing** — many concurrent connections and many streams per connection.

**Protocol**: libp2p over QUIC (`/quic-v1` / `/quic-v1/webtransport`).


### 2.2 Required API Surface

The contract is four public Dart classes consumed by `dart_ipfs` and implemented by `dart_quic`. The authoritative API definitions are in [DART_API_SPEC.md §2.8](../specs/DART_API_SPEC.md#28-libp2p-api). The following summarizes their roles in the integration:

- `Libp2pQuicTransport`: Entry point for listen/dial operations.
- `Libp2pConnection`: Represents an established peer connection.
- `Libp2pStream`: A bidirectional protocol stream within a connection.
- `PeerId`: libp2p peer identity (multihash public key fingerprint).

#### Integration-specific additions

`dart_ipfs` expects the following behaviors beyond the base API:

- `listen()` must accept `/ip4/.../udp/.../quic-v1` and `/ip6/.../udp/.../quic-v1` multiaddrs.
- `dial()` must perform peer authentication via the libp2p TLS 1.3 extension.
- `openStream()` must internally negotiate the protocol via multistream-select.
- `close()` on the transport must gracefully close all active connections.


### 2.3 Protocol Negotiation

`multistream-select` is handled internally by `dart_quic`. The consumer passes the protocol ID to `openStream()` and receives a `Libp2pStream` with the negotiated `protocol` value. `StreamError` is emitted on negotiation failure.


### 2.4 Events `dart_ipfs` Needs

```dart
abstract class Libp2pEvent {
  final PeerId peerId;
  Libp2pEvent(this.peerId);
}

class PeerConnected extends Libp2pEvent {
  final Libp2pConnection connection;
  PeerConnected(super.peerId, this.connection);
}

class PeerDisconnected extends Libp2pEvent {
  final String? reason;
  PeerDisconnected(super.peerId, {this.reason});
}

class StreamError extends Libp2pEvent {
  final Libp2pStream? stream;
  final Object error;
  StreamError(super.peerId, {this.stream, required this.error});
}
```


### 2.5 Constraints

- **Pure Dart**: public API and default transport must not depend on `dart:ffi` or native code in the core path. Native acceleration may be an optional backend behind the same interface.
- **50+ simultaneous connections**: the transport must sustain at least 50 concurrent authenticated connections and many streams per connection.
- **Connection migration**: the QUIC connection manager must support path migration so mobile peers survive network transitions.






## 3. References

- [LIBP2P_QUIC_SPEC.md](../specs/LIBP2P_QUIC_SPEC.md) — wire and handshake details
- [DART_API_SPEC.md](../specs/DART_API_SPEC.md) — general Dart API conventions
- [MODULE_OVERVIEW.md](MODULE_OVERVIEW.md) — internal subsystem layering
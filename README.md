# dart_quic

A comprehensive, pure-Dart QUIC protocol stack specification and architecture.

## Charter

`dart_quic` exists to define the institution-level, deep-research-backed,
interoperable, pure-Dart implementation of QUIC, HTTP/3, and WebTransport for the
Dart ecosystem. This repository intentionally remains at the
**specification/documentation stage**; code implementation follows only after
the architecture, protocol mapping, security model, and test strategy are
exhaustively documented.

## Scope

1. **QUIC transport** (RFC 9000, RFC 9001, RFC 9002) — wire encoding, packet
   protection, handshake, streams, flow control, congestion control.
2. **HTTP/3** (RFC 9114) — mapping HTTP semantics onto QUIC.
3. **WebTransport** (draft-ietf-webtrans-http3) — datagrams, bidirectional and
   unidirectional streams.
4. **libp2p QUIC** integration — multiaddr formats, security handshake (TLS
   1.3 with embedded peer public key), stream mapping.
5. **Dart-native API** design — `dart:io` integration, `Stream`/`Future` idioms,
   `dart:ffi` avoidance, zero native dependencies.

## Document Structure

| Directory | Contents |
|-----------|----------|
| `doc/specs/` | Formal specifications for each subsystem. |
| `doc/research/` | Deep research notes, RFC summaries, prior-art analysis. |
| `doc/architecture/` | Module design, data flow, API surface, roadmap. |

## Status

Specification stage. No implementation code is present.

## License

MIT — see `LICENSE`.

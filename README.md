# dart_quic

A comprehensive, pure-Dart QUIC protocol stack specification and architecture.

## Charter

`dart_quic` is a specification and architecture for a pure-Dart QUIC, HTTP/3,
and WebTransport implementation. This repository currently contains only
documentation and specifications; code implementation will follow once the
design, security model, and test strategy are documented.

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

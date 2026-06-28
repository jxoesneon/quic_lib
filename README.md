# quic_lib

A comprehensive, pure-Dart QUIC protocol stack specification and architecture.

## Charter

`quic_lib` is a pure-Dart implementation of QUIC (RFC 9000), HTTP/3 (RFC 9114),
WebTransport (RFC 9220), and libp2p QUIC transport. The codebase is fully
implemented with comprehensive tests and security hardening.

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
| `doc/specs/` | Formal specifications for each subsystem (21 files). |
| `doc/research/` | Consolidated RFC summaries and prior-art analysis (1 file). |
| `doc/architecture/` | Module design, data flow, API surface (5 files). |

## Status

**Version 1.2.0** — Full implementation with 1,685 passing tests across QUIC wire format, crypto, connection management, recovery, HTTP/3, WebTransport, and libp2p transport. See `CHANGELOG.md` and `SECURITY_FIXES.md` for the latest updates.

## Installation

Add `quic_lib` to your `pubspec.yaml`:

```yaml
dependencies:
  quic_lib: ^1.2.0
```

Requires Dart SDK `^3.0.0`.

## Quickstart

```dart
import 'package:quic_lib/quic_lib.dart';

void main() async {
  // Create a QUIC endpoint bound to a local address.
  final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);

  // Connect to a remote peer.
  final connection = await endpoint.connect(
    InternetAddress.loopbackIPv4,
    4433,
  );

  // Open a bidirectional stream and send data.
  final stream = connection.openBidirectionalStream();
  stream.write(Uint8List.fromList([1, 2, 3]));
  await stream.done;

  // Clean up.
  connection.close();
  endpoint.close();
}
```

See `example/echo_client.dart` and `example/echo_server.dart` for complete examples.

## Testing

Run the full test suite:

```bash
dart test
```

Run with coverage:

```bash
dart test --coverage=coverage
dart run coverage:format_coverage --in=coverage --out=coverage/lcov.info --lcov
```

## Contributing

Contributions are welcome. Please read the architecture overview in `ARCHITECTURE.md` and security guidelines in `SECURITY.md` before submitting changes. All PRs must pass:

1. `dart analyze` — zero issues.
2. `dart test` — all tests green.
3. `dart format --set-exit-if-changed` — formatting clean.

## License

MIT — see `LICENSE`.

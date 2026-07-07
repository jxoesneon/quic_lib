# quic_lib Examples

This directory contains runnable example applications demonstrating how to use
the `quic_lib` package.

## Examples

- **`echo_client.dart`** — Sends an encrypted QUIC STREAM frame over a
  loopback UDP socket and waits for the server to echo it back.
- **`echo_server.dart`** — Listens on `127.0.0.1:12345`, receives an encrypted
  STREAM frame, and echoes the payload back to the client.
- **`echo_common.dart`** — Shared test configuration used by the echo pair.
  It sets a fixed destination connection ID and derives deterministic
  application keys so the two examples can perform a real encrypted
  round-trip without requiring a full TLS handshake.
- **`http3_client.dart`** — Demonstrates wrapping a [QuicConnection] in an
  [Http3Connection], exchanging SETTINGS, sending an HTTP/3 request, and
  reading the staged response.

## Running the examples

### Echo server

```bash
dart run example/echo_server.dart
```

The server will listen on `127.0.0.1:12345`. Press `Ctrl+C` to stop it.

### Echo client

In a separate terminal, run:

```bash
dart run example/echo_client.dart
```

The client will bind to an ephemeral port, send the message `Hello, QUIC!`
over an encrypted QUIC STREAM frame, and print the echoed reply.

### HTTP/3 client

```bash
dart run example/http3_client.dart
```

The client will bind to an ephemeral port, connect to `127.0.0.1:4433`, and
stage an HTTP/3 GET request over a new bidirectional stream.

## Notes and limitations

The echo examples are real end-to-end encrypted UDP exchanges, but they use
deterministic test keys so they can run without a full TLS handshake. The
public API does not yet expose a way to register externally keyed
connections with [QuicEndpoint], so the examples use the lower-level
[RawDatagramSocket] and [QuicConnection] APIs directly, the same building
blocks used by the package's end-to-end tests. A production implementation
would complete the handshake and derive fresh 1-RTT keys through
[QuicEndpoint].

### WebTransport and libp2p examples

No dedicated WebTransport or libp2p examples are provided. Both subsystems
are available through the public API (`package:quic_lib/webtransport.dart` and
`package:quic_lib/libp2p.dart`), but writing a self-contained, runnable
example requires a coordinating peer and a full handshake, which is currently
beyond the API surface demonstrated here. Historical roadmap references to
`example/webtransport_chat/` and `example/libp2p_dial/` do not exist in this
repository.

See the package [README](../README.md) and [doc/](../doc/) folder for the full
architecture and roadmap.

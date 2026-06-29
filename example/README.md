# quic_lib Examples

This directory contains minimal example applications demonstrating how to use the `quic_lib` package.

## Examples

- **`echo_client.dart`** — Demonstrates creating a [QuicEndpoint], connecting to a server, opening a bidirectional stream, and staging data through the `QuicSendStream` API.
- **`echo_server.dart`** — Demonstrates binding a [QuicEndpoint] to a local address, polling active connections, registering each connection in its own isolate, and printing incoming stream data.
- **`http3_client.dart`** — Demonstrates wrapping a [QuicConnection] in an [Http3Connection], exchanging SETTINGS, sending an HTTP/3 request, and reading the staged response.

## Running the examples

### Echo server

```bash
dart run echo_server.dart
```

The server will listen on `127.0.0.1:4433`. Press `Ctrl+C` to stop it gracefully.

### Echo client

In a separate terminal, run:

```bash
dart run echo_client.dart
```

The client will bind to an ephemeral port, connect to `127.0.0.1:4433`, open a bidirectional stream, and stage a "Hello, QUIC!" message via the stream API.

### HTTP/3 client

```bash
dart run http3_client.dart
```

The client will bind to an ephemeral port, connect to `127.0.0.1:4433`, and stage an HTTP/3 GET request over a new bidirectional stream.

## Note

These examples are scaffolding that demonstrate the public API surface. Some end-to-end wire paths (such as fully completing a handshake over UDP) may still be under active development. See the package [README](../README.md) and [doc/](../doc/) folder for the full architecture and roadmap.

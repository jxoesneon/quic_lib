# quic_lib

[![pub package](https://img.shields.io/pub/v/quic_lib.svg)](https://pub.dev/packages/quic_lib)
[![Build Status](https://img.shields.io/github/actions/workflow/status/jxoesneon/quic_lib/ci.yml)](https://github.com/jxoesneon/quic_lib/actions)
[![Coverage](https://img.shields.io/codecov/c/github/jxoesneon/quic_lib/main)](https://codecov.io/gh/jxoesneon/quic_lib)
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg)](https://opensource.org/licenses/MIT)

A comprehensive, pure-Dart QUIC protocol stack specification and architecture.

`quic_lib` is a pure-Dart implementation of [QUIC](https://www.rfc-editor.org/rfc/rfc9000.html) (RFC 9000), [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) (RFC 9114), [WebTransport](https://www.rfc-editor.org/rfc/rfc9220.html) (RFC 9220), and libp2p QUIC transport. The codebase is fully implemented with comprehensive tests and security hardening — zero native dependencies, zero `dart:ffi`.

## Table of contents

- [Features](#features)
- [Platform support](#platform-support)
- [Installation](#installation)
- [Package structure](#package-structure)
- [Quickstart](#quickstart)
  - [QUIC transport](#quic-transport)
  - [HTTP/3 request](#http3-request)
  - [WebTransport](#webtransport)
  - [libp2p](#libp2p)
- [Feature matrix](#feature-matrix)
- [API documentation](#api-documentation)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

1. **QUIC transport** (RFC 9000, RFC 9001, RFC 9002) — wire encoding, packet protection, handshake, streams, flow control, congestion control.
2. **HTTP/3** (RFC 9114) — mapping HTTP semantics onto QUIC with QPACK header compression.
3. **WebTransport** (RFC 9220) — datagrams, bidirectional and unidirectional streams over HTTP/3.
4. **libp2p QUIC** integration — multiaddr formats, security handshake, stream mapping.
5. **Dart-native API** design — `dart:io` integration, `Stream`/`Future` idioms, no native dependencies.

### Advanced features

- **QPACK encoder/decoder stream instructions** (RFC 9204) — dynamic table capacity updates, insertions with name references, and duplicate instructions.
- **ORIGIN and PRIORITY_UPDATE frames** (RFC 9412 / RFC 9218) — origin management and priority signalling for HTTP/3.
- **RFC 9368 Compatible Version Negotiation** — negotiate QUIC versions without breaking the handshake.
- **CUBIC congestion control** (RFC 8312) — production-grade congestion controller with pacing.
- **QUIC bit greasing** (RFC 9287) — reserved bit randomisation for future extensibility.
- **ECN processing** (RFC 9000 Section 13.4) — explicit congestion notification on supported paths.
- **libp2p multistream-select and certificate generation** — TLS extension with Ed25519 peer authentication and ephemeral self-signed certificate generation.
- **WebTransport session support** (RFC 9220) — Extended CONNECT, capsule protocol, and session establishment over HTTP/3.

## Platform support

| Platform | Support | Notes |
|----------|---------|-------|
| Android  | ✅ Full | Native UDP sockets, isolates, full QUIC stack |
| iOS      | ✅ Full | Native UDP sockets, isolates, full QUIC stack |
| Linux    | ✅ Full | Native UDP sockets, isolates, full QUIC stack |
| macOS    | ✅ Full | Native UDP sockets, isolates, full QUIC stack |
| Windows  | ✅ Full | Native UDP sockets, isolates, full QUIC stack |

Requires Dart SDK `^3.0.0`.

> **Why no Web / WASM?**
>
> `quic_lib` is a *wire-format* QUIC implementation — it encodes packets, manages connection IDs, runs the handshake state machine, and handles UDP I/O directly. Browsers intentionally do **not** expose raw UDP sockets to web applications because of fundamental security risks: UDP can be used for DDoS amplification attacks, port scanning, DNS cache poisoning, and firewall bypassing. The web security model requires the browser to own the network stack.
>
> If you need QUIC-like functionality in a browser, use the **WebTransport API** (built into Chrome, Firefox, and Safari). The browser handles the QUIC wire protocol internally and exposes a high-level API. See [doc/WEB_AND_WASM.md](doc/WEB_AND_WASM.md) for a full explanation of the limitation and recommended alternatives.

## Installation

Add `quic_lib` to your `pubspec.yaml`:

```yaml
dependencies:
  quic_lib: ^1.4.0
```

Then run `dart pub get`.

## Package structure

The library is organised into five barrel files so you can import only what you need:

| Import | What you get | When to use |
|--------|--------------|-------------|
| `package:quic_lib/quic_lib.dart` | **Full public API** — wire format, crypto, TLS, connection, streams, recovery, HTTP/3, WebTransport, libp2p | You need everything or aren't sure which subset you need. |
| `package:quic_lib/quic.dart` | QUIC transport core — `QuicEndpoint`, `QuicConnection`, stream scheduler, isolates | You are building a custom protocol directly on QUIC. |
| `package:quic_lib/http3.dart` | HTTP/3 layer — `Http3Connection`, request/response, frames, QPACK | You are building an HTTP/3 client or server. |
| `package:quic_lib/webtransport.dart` | WebTransport — sessions, capsules, stream types | You need unreliable datagrams or WebTransport sessions. |
| `package:quic_lib/libp2p.dart` | libp2p transport — `Libp2pQuicTransport`, `Multiaddr`, `PeerId` | You are integrating with a libp2p network. |

## Quickstart

### QUIC transport

Bind an endpoint, connect to a remote peer, open a stream, and send data:

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:quic_lib/quic_lib.dart';

Future<void> main() async {
  // 1. Bind to an ephemeral local port.
  final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);

  // 2. Connect to a remote server.
  final connection = await endpoint.connect(
    InternetAddress.loopbackIPv4,
    4433,
  );

  // 3. Open a client-initiated bidirectional stream.
  final streamId = connection.openBidirectionalStream();

  // 4. Build a STREAM frame and packetize it.
  final frame = StreamFrame(
    streamId: streamId,
    data: Uint8List.fromList([1, 2, 3]),
    fin: true,
  );
  final packet = await PacketSender.buildPacket(
    frames: [frame],
    space: PacketNumberSpace.application,
    dcid: [],
    packetNumber: connection.allocatePacketNumber(PacketNumberSpace.application),
  );

  print('Prepared ${packet.length} byte packet for stream $streamId');

  // 5. Clean up.
  connection.close();
  endpoint.close();
}
```

See `example/echo_client.dart` and `example/echo_server.dart` for complete runnable examples.

### HTTP/3 request

Import the HTTP/3 barrel and send a request over an existing QUIC connection:

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:quic_lib/quic.dart';
import 'package:quic_lib/http3.dart';

Future<void> main() async {
  // 1. Establish a QUIC connection.
  final endpoint = await QuicEndpoint.bind(InternetAddress.anyIPv4, 0);
  final quicConn = await endpoint.connect(
    InternetAddress.loopbackIPv4,
    4433,
  );

  // 2. Wrap it in an HTTP/3 connection.
  final http3 = Http3Connection(quicConnection: quicConn);
  http3.sendSettings();

  // 3. Build and send a request.
  final request = Http3Request(
    method: 'GET',
    path: '/',
    headers: {'host': 'example.com', 'user-agent': 'quic_lib/1.2.0'},
  );
  final streamId = await http3.sendRequest(request);
  print('Sent request on stream $streamId');

  // 4. Read the response once frames are received.
  final response = http3.getResponse(streamId);
  if (response != null) {
    print('Status: ${response.statusCode}');
  }

  endpoint.close();
}
```

### WebTransport

Create a WebTransport session and exchange capsules:

```dart
import 'dart:typed_data';
import 'package:quic_lib/webtransport.dart';

void main() {
  // 1. Create a session manager.
  final manager = WebTransportSessionManager();

  // 2. Create a new session on a bidirectional stream ID.
  final session = manager.createSession(0);

  // 3. Send a datagram capsule.
  final datagram = session.sendDatagram(Uint8List.fromList([0xDE, 0xAD]));
  print('Datagram capsule type: ${datagram.type}');

  // 4. Gracefully close the session.
  final closeCapsule = session.initiateClose(errorCode: 0);
  manager.routeCapsule(session.sessionId, closeCapsule);

  // 5. Clean up inactive sessions.
  manager.cleanupInactiveSessions();
}
```

### libp2p

Dial or listen using libp2p multiaddrs:

```dart
import 'package:quic_lib/libp2p.dart';

Future<void> main() async {
  // 1. Create the transport.
  final transport = Libp2pQuicTransport();

  // 2. Listen on a multiaddr.
  final local = Multiaddr.parse('/ip4/0.0.0.0/udp/0/quic-v1');
  final incoming = await transport.listen(local);
  incoming.listen((conn) {
    print('Incoming libp2p connection');
    conn.close();
  });

  // 3. Dial a remote peer.
  final remote = Multiaddr.parse('/ip4/127.0.0.1/udp/4433/quic-v1');
  final conn = await transport.dial(remote);
  print('Dialed peer, quic connection: ${conn.quicConnection}');

  // 4. Close the transport.
  await transport.close();
}
```

## Feature matrix

| Feature | Status | Notes |
|---------|--------|-------|
| QUIC wire format (RFC 9000) | ✅ Complete | Long/short headers, all frame types, version negotiation |
| TLS 1.3 handshake (RFC 9001) | ✅ Complete | Client/server hello, certificate verify, finished |
| Packet protection (AES-GCM, ChaCha20-Poly1305) | ✅ Complete | Header protection, key update, retry integrity |
| Stream multiplexing & flow control | ✅ Complete | Bidirectional & unidirectional streams |
| Connection migration | ✅ Complete | Path challenge/response, NAT rebinding |
| Congestion control | ✅ Complete | NewReno, CUBIC (RFC 8312), BBR, Hystart; pacing |
| Loss detection & recovery | ✅ Complete | RttEstimator, LossDetector, PTO scheduler, persistent congestion |
| ECN processing | ✅ Complete | ECT marking, AckEcnFrame validation (RFC 9000 §13.4) |
| HTTP/3 framing (RFC 9114) | ✅ Complete | HEADERS, DATA, SETTINGS, GOAWAY, CANCEL_PUSH, ORIGIN (RFC 9412), PRIORITY_UPDATE (RFC 9218) |
| QPACK header compression | ✅ Complete | Static table, encoder/decoder, stream instructions (RFC 9204) |
| WebTransport capsules (RFC 9220) | ✅ Complete | CLOSE, DRAIN, GOAWAY, REGISTER_BIDIRECTIONAL/UNIDIRECTIONAL_STREAM, DATAGRAM |
| Compatible version negotiation (RFC 9368) | ✅ Complete | VersionInformation, version greasing |
| libp2p multiaddr parsing | ✅ Complete | ip4, ip6, tcp, udp, dns, dns4, dns6, ws, wss, quic, quic-v1, tls, p2p |
| libp2p TLS extension | ✅ Complete | Ed25519 peer authentication, certificate generator |
| libp2p multistream-select | ✅ Complete | `/multistream/1.0.0` protocol negotiation |
| libp2p PeerId (base58/base36) | ✅ Complete | Encoding, decoding, equality |
| 0-RTT | ✅ Complete (wire protocol) | Key derivation (RFC 9001), `NewSessionTicket` (RFC 8446), `buildZeroRttPacket`, `earlyData` TP |
| Server push (HTTP/3) | ✅ Complete | `PUSH_PROMISE`, `CANCEL_PUSH`, `MAX_PUSH_ID` frames; `registerPushPromise` / `hasPushPromise` API |

## API documentation

Full API reference is available at:

* **pub.dev** — browse the generated docs after each release.
* **Local** — run `dart doc` in the package root to generate `doc/api`.

Key classes to explore:

* Transport — `QuicEndpoint`, `QuicConnection`
* HTTP/3 — `Http3Connection`, `Http3Request`
* WebTransport — `WebTransportSession`, `WebTransportSessionManager`
* libp2p — `Libp2pQuicTransport`, `Multiaddr`

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

**1,960+ passing tests** cover QUIC wire format, crypto, connection management, recovery, HTTP/3, WebTransport, and libp2p transport.

## Contributing

Contributions are welcome. Please read the architecture overview in `ARCHITECTURE.md` and security guidelines in `SECURITY.md` before submitting changes. All PRs must pass:

1. `dart analyze` — zero issues.
2. `dart test` — all tests green.
3. `dart format --set-exit-if-changed` — formatting clean.

## License

MIT — see `LICENSE`.

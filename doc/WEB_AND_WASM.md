# Web and WASM Support in quic_lib

## TL;DR

`quic_lib` is a **native-only** package. It does not run on the web or in WASM, and this is an intentional limitation that cannot be worked around with stubs or conditional imports. The QUIC protocol requires raw UDP sockets, which browsers intentionally block for security reasons.

If you need QUIC-like networking in a browser, use the browser's built-in **WebTransport API** instead.

---

## Why browsers block raw UDP (and always will)

The web security model is built on the principle that the **browser owns the network stack**. Web pages are untrusted code that runs on users' machines, so browsers place hard constraints on what network operations are allowed.

Raw UDP is blocked because it enables attacks that are impossible to mitigate at the browser level:

| Attack | How raw UDP enables it | Why browsers can't fix it |
|--------|------------------------|---------------------------|
| **DDoS amplification** | UDP is stateless. A malicious page can send a small forged packet to a public server (e.g., DNS, NTP) with the victim's IP as the source, causing the server to flood the victim with large responses. | The browser cannot verify that the source IP in a UDP packet matches the actual sender. |
| **Port scanning** | Raw UDP lets you probe any port on any IP to discover running services (printers, routers, databases, internal APIs). | This exposes internal network topology that should be invisible to web pages. |
| **DNS cache poisoning** | Forge UDP DNS responses to redirect the user's traffic to attacker-controlled servers. | UDP has no connection state to validate responses against. |
| **NAT/firewall bypass** | UDP hole punching can establish connections through corporate/state firewalls that block TCP. | Firewalls rely on TCP's connection state; UDP bypasses this. |
| **IP spoofing / tracking** | Raw sockets enable fine-grained network fingerprinting and geolocation that HTTP requests do not. | Every UDP packet leaks network topology information. |

These are not hypothetical risks. They are the exact reasons that every major browser vendor (Chromium, Mozilla, Apple, and the W3C TAG) has rejected proposals for raw UDP sockets in the web platform.

### What about Chrome's "Direct Sockets API"?

Chrome has an experimental **Direct Sockets API**, but it is restricted to:
- **Isolated Web Apps** (IWAs) — a special packaging format for enterprise/kiosk apps, not regular web pages
- Requires enterprise policy configuration
- Behind a feature flag
- Not available to standard web applications

This is not a viable path for general-purpose Dart packages.

---

## What browsers provide instead: WebTransport

The W3C **WebTransport API** is the browser's standardised answer to QUIC. It is shipping in:
- Chrome/Edge (stable since 2023)
- Firefox (stable since 2024)
- Safari (stable since 2024)

WebTransport gives you:
- **Unreliable datagrams** — UDP-like, but encrypted and congestion-controlled by the browser's QUIC stack
- **Reliable bidirectional streams** — TCP-like, multiplexed over HTTP/3
- **Reliable unidirectional streams** — one-way ordered data transfer

Under the hood, the browser is running a full QUIC/HTTP3 implementation (usually based on Chromium's `net/quic` or Cloudflare's `quiche`). You don't see packets, connection IDs, or wire format — the browser handles all of that.

### JavaScript example

```javascript
const transport = new WebTransport('https://example.com:4433');
await transport.ready;

// Unreliable datagrams (UDP-like)
const writer = transport.datagrams.writable.getWriter();
writer.write(new Uint8Array([1, 2, 3]));

// Reliable bidirectional stream
const stream = await transport.createBidirectionalStream();
const reader = stream.readable.getReader();
const { value } = await reader.read();
```

### Dart example (using `package:web`)

```dart
import 'package:web/web.dart';

Future<void> main() async {
  final transport = WebTransport('https://example.com:4433');
  await transport.ready.toDart;

  // Unreliable datagrams
  final writer = transport.datagrams.writable.getWriter();
  await writer.write([1, 2, 3].jsify()).toDart;

  // Reliable bidirectional stream
  final stream = await transport.createBidirectionalStream().toDart;
  final reader = stream.readable.getReader();
  final chunk = await reader.read().toDart;
}
```

### Key differences from quic_lib

| Feature | quic_lib (native) | WebTransport (browser) |
|---------|-------------------|------------------------|
| Wire format access | Full control — you encode/decode packets | None — browser handles it |
| Connection IDs | Managed by your code | Managed by the browser |
| TLS handshake | Implemented in Dart | Handled by browser's TLS 1.3 |
| Crypto | Configurable backends (AES-GCM, ChaCha20) | Browser's built-in crypto |
| Congestion control | Your implementation (Cubic, BBR) | Browser's implementation |
| UDP socket | `RawDatagramSocket` (dart:io) | Browser's internal QUIC stack |
| API surface | Low-level: packets, frames, streams | High-level: streams, datagrams |

**WebTransport is not a substitute for quic_lib** — it is a completely different layer of abstraction. If you need low-level QUIC control (e.g., custom congestion control, exotic frame types, or peer-to-peer without a server), you must run on a native platform.

---

## What about WebRTC data channels?

If you need **peer-to-peer** unreliable data transfer in a browser, **WebRTC data channels** are an alternative:

```javascript
const pc = new RTCPeerConnection();
const channel = pc.createDataChannel('data', { ordered: false, maxRetransmits: 0 });
channel.send(new Uint8Array([1, 2, 3]));
```

| Use case | Recommended approach |
|----------|-------------------|
| Client-server QUIC (HTTP/3, WebTransport) | Browser's WebTransport API |
| Peer-to-peer unreliable datagrams | WebRTC data channels |
| Peer-to-peer reliable streams | WebRTC data channels (ordered) |
| Custom wire protocol, low-level control | Native platform + quic_lib |
| Game networking in browser | WebTransport datagrams or WebRTC |

---

## Why quic_lib uses conditional imports anyway

If web is unsupported, why did we add conditional imports for `dart:isolate` and `dart:io`?

1. **Future-proofing**: If browsers ever add raw UDP (extremely unlikely), the code is structured to compile immediately.
2. **Shared code**: Some protocol logic (frame parsing, QPACK, multiaddr formats) is platform-agnostic and can be imported in web projects even if the I/O layer is not used.
3. **Tooling compatibility**: `dart analyze` and IDE autocomplete work correctly across platforms.

The conditional imports do **not** make quic_lib runnable on the web. They only make the *code* compile. Any attempt to create a `QuicEndpoint` or `UdpSocket` on the web will throw `UnsupportedError` at runtime.

---

## Summary

| Question | Answer |
|----------|--------|
| Can quic_lib run in a browser? | **No.** Browsers do not expose raw UDP sockets. |
| Will this ever change? | **No.** Browser vendors have rejected raw UDP for security reasons. |
| What should I use instead? | The browser's built-in **WebTransport API** for client-server QUIC, or **WebRTC** for peer-to-peer. |
| Can I use quic_lib's protocol code on the web? | Partially — frame parsers, QPACK, and multiaddr logic are platform-agnostic, but the connection and I/O layers require native. |
| Does quic_lib support WASM? | **No.** WASM in Dart uses the same browser APIs as JavaScript, so the same UDP limitation applies. |

For native platforms (Android, iOS, Linux, macOS, Windows), quic_lib provides a full, pure-Dart QUIC implementation with zero native dependencies. For the web, use the APIs the browser gives you.

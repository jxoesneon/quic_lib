# WebTransport over HTTP/3 Draft Notes

**Document**: draft-ietf-webtrans-http3 (latest: draft-15)  
**Working Group**: IETF WebTransport (webtrans)  
**Status**: Active Internet-Draft (on Standards Track path)  
**Depends on**: RFC 9114 (HTTP/3), RFC 9000 (QUIC), RFC 9297 (HTTP Datagrams)

---

## Abstract

WebTransport over HTTP/3 is a protocol that enables web application clients (constrained by the web security model) to communicate with a remote server using a secure multiplexed transport. It provides unidirectional streams, bidirectional streams, and datagrams, all multiplexed within a single HTTP/3 connection.

---

## Motivation

WebSocket provides a single bidirectional byte stream. For real-time applications (gaming, live media, collaborative editing), developers need:
- **Multiple independent streams** (no head-of-line blocking between messages)
- **Unreliable delivery** (datagrams for latency-sensitive data)
- **Server-initiated streams**
- **Multiplexing** with other HTTP traffic on the same connection

WebTransport over HTTP/3 provides all of these.

---

## Session Establishment (Section 3)

### Prerequisites

1. Both endpoints must support HTTP/3 datagrams: `SETTINGS_H3_DATAGRAM = 1`
2. Both endpoints must support QUIC datagrams: `max_datagram_frame_size > 0` transport parameter
3. Server advertises WebTransport support: `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`

### CONNECT Request

A WebTransport session is established via an extended CONNECT request:

```
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = server.example.com
:path = /game-session
```

- Uses the extended CONNECT mechanism (RFC 8441 adapted for HTTP/3).
- The server responds with a 2xx status to accept.
- The CONNECT stream becomes the **session stream** — its lifetime bounds the session.

---

## Features (Section 4)

### 4.1 Datagrams

- Sent using HTTP Datagrams (RFC 9297) associated with the session's CONNECT stream.
- Unreliable, unordered delivery.
- Size limited by `max_datagram_frame_size` transport parameter.
- Format: Quarter Stream ID (of CONNECT stream) + payload.

### 4.2 Unidirectional Streams

Either endpoint can open unidirectional QUIC streams associated with the session:

```
WebTransport Unidirectional Stream {
  Signal Value (i) = 0x54,     // identifies as WT uni stream
  Session ID (i),              // CONNECT stream ID
  Application Payload (..)
}
```

### 4.3 Bidirectional Streams

**Client-initiated**: Uses a signal value as the first bytes of a client-initiated bidirectional stream:

```
WebTransport Bidirectional Stream (client) {
  Signal Value (i) = 0x41,     // "WT bidi" signal
  Session ID (i),              // CONNECT stream ID  
  Application Payload (..)
}
```

**Server-initiated**: HTTP/3 normally doesn't allow server-initiated bidi streams. WebTransport extends this:

```
WebTransport Bidirectional Stream (server) {
  Signal Value (i) = 0x41,
  Session ID (i),
  Application Payload (..)
}
```

---

## Session Lifecycle

```
Client                                        Server
  |                                             |
  |-- CONNECT :protocol=webtransport ---------->|
  |                                             |
  |<-- 200 OK ---------------------------------|
  |                                             |
  |== SESSION ESTABLISHED ======================|
  |                                             |
  |-- Datagram (unreliable) ------------------->|
  |<-- Datagram (unreliable) -------------------|
  |                                             |
  |-- Open unidirectional stream -------------->|
  |<-- Open unidirectional stream --------------|
  |                                             |
  |-- Open bidirectional stream --------------->|
  |<-- Open bidirectional stream ---------------|
  |                                             |
  |-- CLOSE (reset CONNECT stream) ------------>|
  |                                             |
```

### Session Termination

- Closing or resetting the CONNECT stream terminates the session.
- All associated streams and datagrams are implicitly terminated.
- Server can send `CLOSE_WEBTRANSPORT_SESSION` capsule with an error code and reason.

---

## Multiplexing Multiple Sessions

Multiple WebTransport sessions can share a single HTTP/3 connection:
- Each has its own CONNECT stream (distinct stream ID).
- Streams/datagrams are associated with their session by Session ID.
- Sessions are independent; closing one does not affect others.

---

## Capsule Protocol Integration

WebTransport uses the Capsule Protocol (RFC 9297) on the CONNECT stream for:

| Capsule | Purpose |
|---------|---------|
| `CLOSE_WEBTRANSPORT_SESSION` | Graceful session close with error code + reason |
| `DRAIN_WEBTRANSPORT_SESSION` | Signal intent to close; peer should stop new streams |

---

## Flow Control Considerations

- WebTransport streams are QUIC streams and subject to QUIC flow control.
- Datagrams are not flow-controlled (they are unreliable).
- The HTTP/3 connection's flow control applies to the CONNECT stream carrying capsules.
- Each session's streams consume from the shared QUIC connection flow control budget.

---

## Security Model

- Origin-based: The CONNECT request carries `:authority` and `:path` that identify the server application.
- Certificate validation: Standard HTTPS certificate validation applies.
- CORS-like: The web security model restricts which origins can establish sessions.
- No cross-origin data leakage through multiplexed sessions.

---

## Relevance to dart_quic

1. **Layering**: WebTransport sits on top of HTTP/3, which sits on top of QUIC. The Dart implementation should maintain this layering cleanly.
2. **Session abstraction**: A `WebTransportSession` class should encapsulate:
   - The underlying CONNECT stream
   - Methods to open/accept unidirectional and bidirectional streams
   - Methods to send/receive datagrams
3. **Signal values**: Stream type detection must check for 0x41 (bidi) and 0x54 (uni) prefixes.
4. **Datagram API**: Expose a simple `sendDatagram(Uint8List)` / `Stream<Uint8List> get datagrams` interface.
5. **Multiple sessions**: Support multiplexing multiple sessions on one connection.
6. **Graceful close**: Support CLOSE_WEBTRANSPORT_SESSION and DRAIN capsules.

---

## References

- draft-ietf-webtrans-http3: https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/
- RFC 9297 (HTTP Datagrams): https://www.rfc-editor.org/rfc/rfc9297
- RFC 9114 (HTTP/3): https://www.rfc-editor.org/rfc/rfc9114
- RFC 9221 (QUIC Datagrams): https://www.rfc-editor.org/rfc/rfc9221
- WebTransport Overview: https://datatracker.ietf.org/doc/draft-ietf-webtrans-overview/

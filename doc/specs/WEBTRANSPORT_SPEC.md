---
title: "WebTransport Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "WebTransport over HTTP/3"
rfc_basis:
  - "draft-ietf-webtrans-http3"
  - "RFC 9220"
  - "RFC 9297"
  - "RFC 9221"
dependencies:
  - "ERROR_REGISTRY.md"
  - "ROADMAP.md"
---

# WebTransport Specification



## 1. Purpose

WebTransport is the web next real-time transport, offering multiple independent streams and unreliable datagrams over a single HTTP/3 connection. Dart developers building games, collaboration tools, or streaming clients need this capability, but no Dart implementation exists. This spec defines the session management, stream dispatch, and capsule protocol that bring WebTransport to the Dart ecosystem.

## 2. Detailed Specification
### 2.1 Architecture

```
┌─────────────────────────────────────┐
│       Dart WebTransport API         │
├─────────────────────────────────────┤
│     Session Manager                 │  (multiple sessions per connection)
├─────────────────────────────────────┤
│     Stream Dispatcher               │  (route by signal value + session ID)
├─────────────────────────────────────┤
│     Datagram Handler                │  (RFC 9221 QUIC datagrams)
├─────────────────────────────────────┤
│     HTTP/3 Layer                    │  (CONNECT, SETTINGS)
├─────────────────────────────────────┤
│     QUIC Transport                  │  (streams, datagrams)
└─────────────────────────────────────┘
```

---


### 2.2 Prerequisites

#### 2.2.1 Transport Parameters

| Parameter | Requirement |
|-----------|-------------|
| `max_datagram_frame_size` | > 0 (both endpoints) |

#### 2.2.2 HTTP/3 Settings

| Setting | Requirement |
|---------|-------------|
| `SETTINGS_H3_DATAGRAM` | = 1 (both endpoints) |
| `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` | > 0 (server) |
| `SETTINGS_ENABLE_CONNECT_PROTOCOL` | = 1 (server) |

---


### 2.3 Session Establishment

#### 2.3.1 Client Request

The client initiates a WebTransport session via an extended CONNECT request on a bidirectional QUIC stream:

```http
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = server.example.com
:path = /session-endpoint
origin = https://client.example.com
```

#### 2.3.2 Server Response

```http
:status = 200
sec-webtransport-http3-draft = draft02
```

- 2xx status: session accepted.
- 4xx/5xx: session rejected (stream can be reset).

#### 2.3.3 Session Stream

The CONNECT stream becomes the **session stream**:
- Its stream ID serves as the Session ID for associated streams/datagrams.
- Closing or resetting this stream terminates the session.
- Capsules (CLOSE, DRAIN) are sent on this stream.

---


### 2.4 Streams

#### 2.4.1 Bidirectional Streams

**Client-initiated**:
```
First bytes: 0x41 (signal value, varint)
Next bytes: Session ID (varint) = CONNECT stream ID
Remaining: Application payload
```

**Server-initiated**:
```
First bytes: 0x41 (signal value, varint)
Next bytes: Session ID (varint) = CONNECT stream ID
Remaining: Application payload
```

#### 2.4.2 Unidirectional Streams

```
First bytes: 0x54 (signal value, varint)
Next bytes: Session ID (varint) = CONNECT stream ID
Remaining: Application payload
```

Either endpoint can open unidirectional streams.

#### 2.4.3 Stream Association

All WebTransport streams carry a Session ID that associates them with a specific session. Implementations MUST verify the Session ID refers to an active session.

---


### 2.5 Datagrams

#### 2.5.1 Format

WebTransport datagrams use HTTP Datagrams (RFC 9297):

```
HTTP Datagram {
  Quarter Stream ID (i),    // CONNECT stream ID / 4
  Payload (..)              // application datagram
}
```

Carried in QUIC DATAGRAM frames (RFC 9221).

#### 2.5.2 Properties

- **Unreliable**: No retransmission.
- **Unordered**: May arrive out of order or not at all.
- **Size-limited**: By `max_datagram_frame_size` transport parameter minus overhead.
- **Not flow-controlled**: QUIC datagrams bypass QUIC flow control.
- **Congestion-controlled**: Still subject to congestion control.

#### 2.5.3 Maximum Datagram Size

```
max_payload = max_datagram_frame_size - quic_overhead - http_datagram_header
```

Where `http_datagram_header` = length of the encoded Quarter Stream ID.

---


### 2.6 Session Lifecycle

#### 2.6.1 States

```
Connecting → Established → Draining → Closed
                              ↑
                   (DRAIN capsule received)
```

#### 2.6.2 Termination

#### Graceful Close (initiator)

1. Send `CLOSE_WEBTRANSPORT_SESSION` capsule on the session stream.
2. All associated streams are implicitly reset.
3. Session stream FINs.

```
CLOSE_WEBTRANSPORT_SESSION Capsule {
  Application Error Code (32),
  Application Error Message (..)  // UTF-8
}
```

#### Drain (pre-close signal)

1. Send `DRAIN_WEBTRANSPORT_SESSION` capsule.
2. Peer should stop opening new streams.
3. Existing streams may complete.
4. Eventually followed by CLOSE.

#### Abrupt Close

- Reset the CONNECT stream → immediate session termination.
- All associated streams are reset by QUIC.

---


### 2.7 Multiple Sessions

- Multiple WebTransport sessions can coexist on one HTTP/3 connection.
- Each has a unique CONNECT stream (different stream IDs).
- Limited by `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
- Sessions are fully independent; closing one does not affect others.

---


### 2.8 Dart API

The WebTransport Dart API is defined in [DART_API_SPEC.md §2.7](DART_API_SPEC.md#27-webtransport-api). The following subsections describe how WebTransport capsules and streams map to those interfaces.

---



## 3. Acceptance Criteria

- [ ] Session establishment via extended CONNECT succeeds.
- [ ] Server rejects sessions beyond SETTINGS_WEBTRANSPORT_MAX_SESSIONS.
- [ ] Client-initiated bidirectional streams carry correct signal value (0x41) and session ID.
- [ ] Server-initiated bidirectional streams work correctly.
- [ ] Unidirectional streams carry correct signal value (0x54) and session ID.
- [ ] Datagrams are sent/received with correct Quarter Stream ID encoding.
- [ ] CLOSE_WEBTRANSPORT_SESSION capsule terminates session gracefully.
- [ ] DRAIN capsule signals intent to close.
- [ ] Resetting CONNECT stream terminates session and all associated streams.
- [ ] Multiple concurrent sessions on one connection are isolated.
- [ ] Max datagram size is correctly calculated and enforced.

---


## 4. Security Considerations

- Validate origin header on server side to prevent cross-origin attacks.
- Enforce maximum session count to prevent resource exhaustion.
- Datagram size limits must be enforced to prevent buffer overflows.
- Session ID validation: reject streams/datagrams referencing non-existent sessions.
- Rate-limit session creation attempts from a single client.

---


## 5. Dependencies

- HTTP/3 layer (HTTP3_SPEC.md): Extended CONNECT, SETTINGS, stream management.
- QUIC Datagrams (RFC 9221): DATAGRAM frame support in QUIC transport.
- QUIC Streams (QUIC_STREAMS_SPEC.md): Bidirectional and unidirectional streams.
- Capsule Protocol (RFC 9297): For session control messages.

---




## Used By

- [ERROR_REGISTRY.md](ERROR_REGISTRY.md) — Defines WebTransport capsule types and session lifecycle.
- [ROADMAP.md](ROADMAP.md) — Lists WEBTRANSPORT_SPEC as a formal specification deliverable.
## 6. Testing Strategy

- Unit: Signal value encoding/decoding, datagram framing.
- Integration: Full session lifecycle (connect → streams → datagrams → close).
- Interop: Test against Chromium's WebTransport implementation.
- Stress: Many concurrent sessions, high datagram throughput.
- Error paths: Reject invalid session IDs, handle abrupt disconnects.

---


## 7. References

- draft-ietf-webtrans-http3: https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/
- RFC 9297 (HTTP Datagrams): https://www.rfc-editor.org/rfc/rfc9297
- RFC 9221 (QUIC Datagrams): https://www.rfc-editor.org/rfc/rfc9221
- WebTransport Overview: https://web.dev/webtransport/
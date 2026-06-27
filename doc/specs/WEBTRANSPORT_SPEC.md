# WebTransport Specification

**Version**: 1.0-draft  
**Status**: Specification  
**Basis**: draft-ietf-webtrans-http3, RFC 9297, RFC 9221  
**Subsystem**: WebTransport over HTTP/3

---

## 1. Purpose

This document specifies the WebTransport layer for `dart_quic`: session establishment via extended CONNECT, bidirectional and unidirectional stream management, datagram support, session lifecycle, and the Dart API.

---

## 2. Architecture

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

## 3. Prerequisites

### 3.1 Transport Parameters

| Parameter | Requirement |
|-----------|-------------|
| `max_datagram_frame_size` | > 0 (both endpoints) |

### 3.2 HTTP/3 Settings

| Setting | Requirement |
|---------|-------------|
| `SETTINGS_H3_DATAGRAM` | = 1 (both endpoints) |
| `SETTINGS_WEBTRANSPORT_MAX_SESSIONS` | > 0 (server) |
| `SETTINGS_ENABLE_CONNECT_PROTOCOL` | = 1 (server) |

---

## 4. Session Establishment

### 4.1 Client Request

The client initiates a WebTransport session via an extended CONNECT request on a bidirectional QUIC stream:

```http
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = server.example.com
:path = /session-endpoint
origin = https://client.example.com
```

### 4.2 Server Response

```http
:status = 200
sec-webtransport-http3-draft = draft02
```

- 2xx status: session accepted.
- 4xx/5xx: session rejected (stream can be reset).

### 4.3 Session Stream

The CONNECT stream becomes the **session stream**:
- Its stream ID serves as the Session ID for associated streams/datagrams.
- Closing or resetting this stream terminates the session.
- Capsules (CLOSE, DRAIN) are sent on this stream.

---

## 5. Streams

### 5.1 Bidirectional Streams

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

### 5.2 Unidirectional Streams

```
First bytes: 0x54 (signal value, varint)
Next bytes: Session ID (varint) = CONNECT stream ID
Remaining: Application payload
```

Either endpoint can open unidirectional streams.

### 5.3 Stream Association

All WebTransport streams carry a Session ID that associates them with a specific session. Implementations MUST verify the Session ID refers to an active session.

---

## 6. Datagrams

### 6.1 Format

WebTransport datagrams use HTTP Datagrams (RFC 9297):

```
HTTP Datagram {
  Quarter Stream ID (i),    // CONNECT stream ID / 4
  Payload (..)              // application datagram
}
```

Carried in QUIC DATAGRAM frames (RFC 9221).

### 6.2 Properties

- **Unreliable**: No retransmission.
- **Unordered**: May arrive out of order or not at all.
- **Size-limited**: By `max_datagram_frame_size` transport parameter minus overhead.
- **Not flow-controlled**: QUIC datagrams bypass QUIC flow control.
- **Congestion-controlled**: Still subject to congestion control.

### 6.3 Maximum Datagram Size

```
max_payload = max_datagram_frame_size - quic_overhead - http_datagram_header
```

Where `http_datagram_header` = length of the encoded Quarter Stream ID.

---

## 7. Session Lifecycle

### 7.1 States

```
Connecting → Established → Draining → Closed
                              ↑
                   (DRAIN capsule received)
```

### 7.2 Termination

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

## 8. Multiple Sessions

- Multiple WebTransport sessions can coexist on one HTTP/3 connection.
- Each has a unique CONNECT stream (different stream IDs).
- Limited by `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
- Sessions are fully independent; closing one does not affect others.

---

## 9. Dart API

```dart
/// Client-side session establishment
abstract class WebTransportClient {
  static Future<WebTransportSession> connect(
    Uri uri, {
    Map<String, String>? headers,
  });
}

/// Server-side session acceptance
abstract class WebTransportServer {
  static Future<WebTransportServer> bind(
    InternetAddress address,
    int port, {
    required SecurityContext securityContext,
    int maxSessions = 100,
  });
  
  Stream<WebTransportSession> get sessions;
  Future<void> close();
}

/// A single WebTransport session
abstract class WebTransportSession {
  /// Session ID (the CONNECT stream ID)
  int get sessionId;
  
  /// Bidirectional streams
  Future<WebTransportBidiStream> openBidirectionalStream();
  Stream<WebTransportBidiStream> get incomingBidirectionalStreams;
  
  /// Unidirectional streams
  Future<WebTransportSendStream> openUnidirectionalStream();
  Stream<WebTransportReceiveStream> get incomingUnidirectionalStreams;
  
  /// Datagrams
  void sendDatagram(List<int> data);
  Stream<List<int>> get datagrams;
  int get maxDatagramSize;
  
  /// Lifecycle
  Future<void> close({int errorCode = 0, String reason = ''});
  Future<void> get closed;  // completes when session ends
  WebTransportCloseInfo? get closeInfo;
}

class WebTransportBidiStream {
  Stream<List<int>> get inbound;
  StreamSink<List<int>> get outbound;
  Future<void> close();
  Future<void> reset(int errorCode);
}

class WebTransportSendStream {
  StreamSink<List<int>> get outbound;
  Future<void> close();
  Future<void> reset(int errorCode);
}

class WebTransportReceiveStream {
  Stream<List<int>> get inbound;
  Future<void> stopSending(int errorCode);
}

class WebTransportCloseInfo {
  final int errorCode;
  final String reason;
}
```

---

## 10. Acceptance Criteria

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

## 11. Security Considerations

- Validate origin header on server side to prevent cross-origin attacks.
- Enforce maximum session count to prevent resource exhaustion.
- Datagram size limits must be enforced to prevent buffer overflows.
- Session ID validation: reject streams/datagrams referencing non-existent sessions.
- Rate-limit session creation attempts from a single client.

---

## 12. Dependencies

- HTTP/3 layer ([HTTP3_SPEC.md](./HTTP3_SPEC.md)): Extended CONNECT, SETTINGS, stream management.
- QUIC Datagrams (RFC 9221): DATAGRAM frame support in QUIC transport.
- QUIC Streams ([QUIC_STREAMS_SPEC.md](./QUIC_STREAMS_SPEC.md)): Bidirectional and unidirectional streams.
- Capsule Protocol (RFC 9297): For session control messages.

---

## 13. Testing Strategy

- Unit: Signal value encoding/decoding, datagram framing.
- Integration: Full session lifecycle (connect → streams → datagrams → close).
- Interop: Test against Chromium's WebTransport implementation.
- Stress: Many concurrent sessions, high datagram throughput.
- Error paths: Reject invalid session IDs, handle abrupt disconnects.

---

## References

- draft-ietf-webtrans-http3: https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/
- RFC 9297 (HTTP Datagrams): https://www.rfc-editor.org/rfc/rfc9297
- RFC 9221 (QUIC Datagrams): https://www.rfc-editor.org/rfc/rfc9221
- WebTransport Overview: https://web.dev/webtransport/

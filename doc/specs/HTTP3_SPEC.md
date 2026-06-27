---
title: "HTTP/3 Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "HTTP/3 Protocol Layer"
rfc_basis:
  - "RFC 9114"
  - "RFC 9204 (QPACK)"
dependencies:
  - "ERROR_REGISTRY.md"
  - "ROADMAP.md"
  - "WEBTRANSPORT_SPEC.md"
---

# HTTP/3 Specification



## 1. Purpose

HTTP/3 is becoming the default for modern web infrastructure, yet Dart has no pure-Dart implementation. Without a specified HTTP/3 layer, dart_quic would remain a low-level transport with no path to serving web traffic or interoping with browsers. This spec defines the mapping from QUIC streams to HTTP semantics, enabling Dart servers and clients to speak the same protocol as CDN edge nodes.

## 2. Detailed Specification
### 2.1 Architecture

```
┌────────────────────────────────────┐
│        Dart HTTP/3 API             │  (Http3Client, Http3Server)
├────────────────────────────────────┤
│      Request/Response Layer        │  (headers, body, trailers)
├────────────────────────────────────┤
│         QPACK Codec               │  (encode/decode headers)
├────────────────────────────────────┤
│     HTTP/3 Frame Layer             │  (DATA, HEADERS, SETTINGS...)
├────────────────────────────────────┤
│     Stream Type Dispatcher         │  (control, QPACK, request, push)
├────────────────────────────────────┤
│       QUIC Transport               │  (from [QUIC_STREAMS_SPEC.md](./QUIC_STREAMS_SPEC.md))
└────────────────────────────────────┘
```

---


### 2.2 Stream Mapping (RFC 9114 Section 6)

#### 2.2.1 Required Streams

Each endpoint MUST open exactly these unidirectional streams:

| Stream | Type ID | Direction | Purpose |
|--------|---------|-----------|---------|
| Control | 0x00 | Both send one | SETTINGS, GOAWAY, MAX_PUSH_ID |
| QPACK Encoder | 0x02 | Both send one | Dynamic table update instructions |
| QPACK Decoder | 0x03 | Both send one | Acknowledgments to encoder |

#### 2.2.2 Request Streams

- Each HTTP request/response uses one **client-initiated bidirectional** QUIC stream.
- Request format: HEADERS frame → optional DATA frames → optional trailing HEADERS frame.
- Response format: HEADERS frame → optional DATA frames → optional trailing HEADERS frame.

#### 2.2.3 Push Streams

- Server-initiated unidirectional streams with type ID 0x01.
- Format: Push ID (i) → HEADERS frame → DATA frames.
- Client limits push IDs via MAX_PUSH_ID.

#### 2.2.4 Stream Type Detection

First varint on a unidirectional stream indicates its type:

```
stream_type = read_varint(stream)
switch stream_type:
  0x00 → control stream
  0x01 → push stream
  0x02 → QPACK encoder stream
  0x03 → QPACK decoder stream
  other → unknown (ignore per RFC 9114 Section 6.2)
```

---


### 2.3 HTTP/3 Frame Format

```
HTTP/3 Frame {
  Type (i),      // variable-length integer
  Length (i),    // variable-length integer (payload length)
  Payload (..)   // exactly Length bytes
}
```

#### 2.3.1 DATA Frame (Type 0x00)

```
DATA { Payload (..) }
```
Carries request/response body data.

#### 2.3.2 HEADERS Frame (Type 0x01)

```
HEADERS { Encoded Field Section (..) }
```
Contains QPACK-encoded HTTP fields.

#### 2.3.3 CANCEL_PUSH Frame (Type 0x03)

```
CANCEL_PUSH { Push ID (i) }
```
Sent on control stream to cancel a server push.

#### 2.3.4 SETTINGS Frame (Type 0x04)

```
SETTINGS {
  Setting {
    Identifier (i),
    Value (i)
  } * N
}
```

Sent as the **first frame** on each control stream.

| Identifier | Name | Default |
|-----------|------|---------|
| 0x01 | SETTINGS_QPACK_MAX_TABLE_CAPACITY | 0 |
| 0x06 | SETTINGS_MAX_FIELD_SECTION_SIZE | unlimited |
| 0x07 | SETTINGS_QPACK_BLOCKED_STREAMS | 0 |

#### 2.3.5 GOAWAY Frame (Type 0x07)

```
GOAWAY { Stream ID/Push ID (i) }
```
Initiates graceful shutdown. The ID indicates the last stream/push the sender will process.

#### 2.3.6 MAX_PUSH_ID Frame (Type 0x0d)

```
MAX_PUSH_ID { Push ID (i) }
```
Client tells server the maximum Push ID it will accept.

---


### 2.4 QPACK Integration

#### 2.4.1 Encoding Request Headers

```dart
// Pseudo-headers (required for requests)
:method = GET
:scheme = https
:authority = example.com
:path = /resource

// Regular headers
accept = application/json
user-agent = dart_quic/1.0
```

#### 2.4.2 Encoding Response Headers

```dart
// Pseudo-header
:status = 200

// Regular headers
content-type = application/json
content-length = 1234
```

#### 2.4.3 QPACK Streams

- Encoder stream: Sends instructions to add entries to the dynamic table.
- Decoder stream: Sends acknowledgments and cancellations.
- Field sections on request streams reference static/dynamic table entries.

#### 2.4.4 Blocking Behavior

- `SETTINGS_QPACK_BLOCKED_STREAMS`: Maximum streams that can block waiting for dynamic table updates.
- If set to 0: Only static table references allowed (no blocking, lower compression).
- If > 0: Streams may block until the required insert count is reached.

---


### 2.5 Connection Lifecycle

#### 2.5.1 Initialization

```
1. QUIC connection established (1-RTT complete)
2. Both endpoints open control stream
3. Both send SETTINGS as first frame on control stream
4. Both open QPACK encoder and decoder streams
5. Connection ready for requests
```

#### 2.5.2 Request/Response

```
Client:
  1. Open bidirectional QUIC stream
  2. Send HEADERS frame (encoded request headers)
  3. Send DATA frames (request body, if any)
  4. Send trailing HEADERS frame (if any)
  5. Close send side (FIN)

Server:
  1. Accept bidirectional QUIC stream
  2. Read HEADERS frame (decode request)
  3. Read DATA frames (request body)
  4. Send HEADERS frame (encoded response headers)
  5. Send DATA frames (response body)
  6. Send trailing HEADERS frame (if any)
  7. Close send side (FIN)
```

#### 2.5.3 Graceful Shutdown

```
1. Endpoint sends GOAWAY(last_stream_id)
2. Peer stops creating new streams > last_stream_id
3. Existing streams complete normally
4. Connection closes when all streams done
```

---


### 2.6 Priority Signaling (RFC 9218)

HTTP/3 replaces the HTTP/2 priority scheme with the Extensible Prioritization Scheme (RFC 9218).

#### 2.6.1 Priority Update Frame (Type 0xF0700)

Sent on the control stream to update a request's priority after the stream is created:

```
PRIORITY_UPDATE Frame {
  Type (i) = 0xF0700,
  Incremental (1),
  Target Stream ID (i),
  Priority Field Value (..),  // e.g., "u=3, i"
}
```

- **Urgency** (`u`): 0 (highest) to 7 (lowest). Default: 3.
- **Incremental** (`i`): Boolean; if true, responses can be interleaved.

#### 2.6.2 Default Priorities

| Resource Type | Default Urgency | Incremental |
|---------------|-----------------|-------------|
| HTML document | 0 | no |
| CSS | 1 | no |
| JavaScript (blocking) | 1 | no |
| Images | 3 | yes |
| Async scripts | 4 | yes |
| Prefetch | 7 | yes |

#### 2.6.3 Scheduling Behavior

- The sender SHOULD send responses in urgency order (lower `u` first).
- Within the same urgency, incremental responses SHOULD be interleaved.
- QUIC stream flow control and congestion control still apply; priority influences scheduler decisions.

---


---


### 2.7 Error Handling

#### 2.6.1 Stream Errors

Reset the individual stream with an HTTP/3 error code via QUIC RESET_STREAM.

#### 2.6.2 Connection Errors

Close the entire connection with an HTTP/3 error code via QUIC CONNECTION_CLOSE (type 0x1d).

#### 2.6.3 Error Codes

| Code | Name | Trigger |
|------|------|---------|
| 0x0100 | H3_NO_ERROR | Clean close |
| 0x0101 | H3_GENERAL_PROTOCOL_ERROR | Unspecified protocol violation |
| 0x0102 | H3_INTERNAL_ERROR | Implementation error |
| 0x0103 | H3_STREAM_CREATION_ERROR | Unexpected stream type |
| 0x0104 | H3_CLOSED_CRITICAL_STREAM | Control/QPACK stream closed |
| 0x0105 | H3_FRAME_UNEXPECTED | Frame in wrong context |
| 0x0106 | H3_FRAME_ERROR | Malformed frame |
| 0x0107 | H3_EXCESSIVE_LOAD | Peer generating too much load |
| 0x0109 | H3_SETTINGS_ERROR | Invalid SETTINGS |
| 0x010a | H3_MISSING_SETTINGS | No SETTINGS received |
| 0x010b | H3_REQUEST_REJECTED | Server rejected request |
| 0x010c | H3_REQUEST_CANCELLED | Application cancelled |
| 0x010d | H3_REQUEST_INCOMPLETE | Stream closed prematurely |
| 0x010e | H3_MESSAGE_ERROR | Malformed HTTP message |

---


### 2.8 Dart API

The HTTP/3 Dart API is defined in [DART_API_SPEC.md §2.6](DART_API_SPEC.md#26-http3-api). The following subsections describe how HTTP/3 frames and settings map to those interfaces.

---



## 3. Acceptance Criteria

- [ ] Control stream is opened and SETTINGS sent on connection establishment.
- [ ] QPACK encoder/decoder streams are opened.
- [ ] HEADERS frames correctly encode/decode HTTP pseudo-headers and regular headers.
- [ ] DATA frames carry request/response bodies.
- [ ] GOAWAY initiates graceful shutdown correctly.
- [ ] Unknown frame types are ignored (not connection error).
- [ ] Unknown stream types are ignored.
- [ ] SETTINGS are enforced (e.g., max field section size).
- [ ] Errors propagate correctly (stream-level vs connection-level).
- [ ] Client can send requests and receive responses.
- [ ] Server can receive requests and send responses.

---


## 4. Security Considerations

- Validate all pseudo-headers (e.g., `:method` must be valid, `:path` must not be empty).
- Enforce max field section size to prevent memory exhaustion.
- Do not log sensitive headers (Authorization, Cookie) at default verbosity.
- QPACK dynamic table contents may leak information — size limits are important.

---


## 5. Dependencies

- QUIC Streams (QUIC_STREAMS_SPEC.md): Bidirectional and unidirectional streams.
- QPACK codec: Header compression/decompression (from RFC_9204_NOTES.md research).
- Wire codec (QUIC_WIRE_SPEC.md): Variable-length integer encoding.

---




## Used By

- [ERROR_REGISTRY.md](ERROR_REGISTRY.md) — References HTTP/3 frame usage and stream mapping.
- [ROADMAP.md](ROADMAP.md) — Lists HTTP3_SPEC as a formal specification deliverable.
- [WEBTRANSPORT_SPEC.md](WEBTRANSPORT_SPEC.md) — WebTransport builds on HTTP/3 layer.
## 6. Testing Strategy

- Unit: Frame encode/decode round-trips.
- Integration: Full request/response exchange over QUIC.
- Interop: Communicate with quic-go, aioquic HTTP/3 servers/clients.
- Conformance: h3spec test suite (https://github.com/kazu-yamamoto/h3spec).
- Stress: Concurrent requests, large bodies, trailer handling.

---


## 7. References

- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114
- RFC 9204 (QPACK): https://www.rfc-editor.org/rfc/rfc9204
- RFC 9110 (HTTP Semantics): https://www.rfc-editor.org/rfc/rfc9110
- h3spec: https://github.com/kazu-yamamoto/h3spec
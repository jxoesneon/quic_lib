# HTTP/3 Specification

**Version**: 1.0-draft  
**Status**: Specification  
**RFC Basis**: RFC 9114, RFC 9204 (QPACK)  
**Subsystem**: HTTP/3 Protocol Layer

---

## 1. Purpose

This document specifies the HTTP/3 protocol layer for `dart_quic`: stream mapping, frame types, QPACK header compression, settings negotiation, error handling, and the Dart API surface for HTTP/3 clients and servers.

---

## 2. Architecture

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
│       QUIC Transport               │  (from QUIC_STREAMS_SPEC.md)
└────────────────────────────────────┘
```

---

## 3. Stream Mapping (RFC 9114 Section 6)

### 3.1 Required Streams

Each endpoint MUST open exactly these unidirectional streams:

| Stream | Type ID | Direction | Purpose |
|--------|---------|-----------|---------|
| Control | 0x00 | Both send one | SETTINGS, GOAWAY, MAX_PUSH_ID |
| QPACK Encoder | 0x02 | Both send one | Dynamic table update instructions |
| QPACK Decoder | 0x03 | Both send one | Acknowledgments to encoder |

### 3.2 Request Streams

- Each HTTP request/response uses one **client-initiated bidirectional** QUIC stream.
- Request format: HEADERS frame → optional DATA frames → optional trailing HEADERS frame.
- Response format: HEADERS frame → optional DATA frames → optional trailing HEADERS frame.

### 3.3 Push Streams

- Server-initiated unidirectional streams with type ID 0x01.
- Format: Push ID (i) → HEADERS frame → DATA frames.
- Client limits push IDs via MAX_PUSH_ID.

### 3.4 Stream Type Detection

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

## 4. HTTP/3 Frame Format

```
HTTP/3 Frame {
  Type (i),      // variable-length integer
  Length (i),    // variable-length integer (payload length)
  Payload (..)   // exactly Length bytes
}
```

### 4.1 DATA Frame (Type 0x00)

```
DATA { Payload (..) }
```
Carries request/response body data.

### 4.2 HEADERS Frame (Type 0x01)

```
HEADERS { Encoded Field Section (..) }
```
Contains QPACK-encoded HTTP fields.

### 4.3 CANCEL_PUSH Frame (Type 0x03)

```
CANCEL_PUSH { Push ID (i) }
```
Sent on control stream to cancel a server push.

### 4.4 SETTINGS Frame (Type 0x04)

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

### 4.5 GOAWAY Frame (Type 0x07)

```
GOAWAY { Stream ID/Push ID (i) }
```
Initiates graceful shutdown. The ID indicates the last stream/push the sender will process.

### 4.6 MAX_PUSH_ID Frame (Type 0x0d)

```
MAX_PUSH_ID { Push ID (i) }
```
Client tells server the maximum Push ID it will accept.

---

## 5. QPACK Integration

### 5.1 Encoding Request Headers

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

### 5.2 Encoding Response Headers

```dart
// Pseudo-header
:status = 200

// Regular headers
content-type = application/json
content-length = 1234
```

### 5.3 QPACK Streams

- Encoder stream: Sends instructions to add entries to the dynamic table.
- Decoder stream: Sends acknowledgments and cancellations.
- Field sections on request streams reference static/dynamic table entries.

### 5.4 Blocking Behavior

- `SETTINGS_QPACK_BLOCKED_STREAMS`: Maximum streams that can block waiting for dynamic table updates.
- If set to 0: Only static table references allowed (no blocking, lower compression).
- If > 0: Streams may block until the required insert count is reached.

---

## 6. Connection Lifecycle

### 6.1 Initialization

```
1. QUIC connection established (1-RTT complete)
2. Both endpoints open control stream
3. Both send SETTINGS as first frame on control stream
4. Both open QPACK encoder and decoder streams
5. Connection ready for requests
```

### 6.2 Request/Response

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

### 6.3 Graceful Shutdown

```
1. Endpoint sends GOAWAY(last_stream_id)
2. Peer stops creating new streams > last_stream_id
3. Existing streams complete normally
4. Connection closes when all streams done
```

---

## 7. Error Handling

### 7.1 Stream Errors

Reset the individual stream with an HTTP/3 error code via QUIC RESET_STREAM.

### 7.2 Connection Errors

Close the entire connection with an HTTP/3 error code via QUIC CONNECTION_CLOSE (type 0x1d).

### 7.3 Error Codes

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

## 8. Dart API

### 8.1 Client

```dart
abstract class Http3Client {
  static Future<Http3Client> connect(Uri uri, {Http3Settings? settings});
  
  Future<Http3Response> send(Http3Request request);
  Stream<Http3PushResponse> get serverPushes;
  
  Future<void> close();  // graceful GOAWAY
}

class Http3Request {
  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final Stream<List<int>>? body;
}

class Http3Response {
  final int statusCode;
  final Map<String, String> headers;
  final Stream<List<int>> body;
  final Map<String, String>? trailers;
}
```

### 8.2 Server

```dart
abstract class Http3Server {
  static Future<Http3Server> bind(InternetAddress address, int port, {
    required SecurityContext securityContext,
    Http3Settings? settings,
  });
  
  Stream<Http3Request> get requests;
  Future<void> close();
}
```

---

## 9. Acceptance Criteria

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

## 10. Security Considerations

- Validate all pseudo-headers (e.g., `:method` must be valid, `:path` must not be empty).
- Enforce max field section size to prevent memory exhaustion.
- Do not log sensitive headers (Authorization, Cookie) at default verbosity.
- QPACK dynamic table contents may leak information — size limits are important.

---

## 11. Dependencies

- QUIC Streams (QUIC_STREAMS_SPEC.md): Bidirectional and unidirectional streams.
- QPACK codec: Header compression/decompression (from RFC_9204_NOTES.md research).
- Wire codec (QUIC_WIRE_SPEC.md): Variable-length integer encoding.

---

## 12. Testing Strategy

- Unit: Frame encode/decode round-trips.
- Integration: Full request/response exchange over QUIC.
- Interop: Communicate with quic-go, aioquic HTTP/3 servers/clients.
- Conformance: h3spec test suite (https://github.com/kazu-yamamoto/h3spec).
- Stress: Concurrent requests, large bodies, trailer handling.

---

## References

- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114
- RFC 9204 (QPACK): https://www.rfc-editor.org/rfc/rfc9204
- RFC 9110 (HTTP Semantics): https://www.rfc-editor.org/rfc/rfc9110
- h3spec: https://github.com/kazu-yamamoto/h3spec

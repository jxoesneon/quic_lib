# RFC 9114 Notes: HTTP/3

**RFC**: 9114  
**Author**: M. Bishop (Ed.)  
**Published**: June 2022  
**Status**: Standards Track  
**Depends on**: RFC 9000, RFC 9204 (QPACK)

---

## Abstract

RFC 9114 defines HTTP/3, the mapping of HTTP semantics over the QUIC transport protocol. It replaces TCP+TLS+HTTP/2 with QUIC, eliminating head-of-line blocking at the transport layer while preserving HTTP's request-response semantics.

---

## Key Differences from HTTP/2

| Feature | HTTP/2 | HTTP/3 |
|---------|--------|--------|
| Transport | TCP + TLS 1.2+ | QUIC (UDP + TLS 1.3) |
| Multiplexing | Stream layer in HTTP/2 framing | Native QUIC streams |
| Header compression | HPACK | QPACK |
| Head-of-line blocking | Present (TCP reordering) | Eliminated (per-stream) |
| Connection setup | TCP handshake + TLS handshake | 1-RTT (combined) |
| Flow control | HTTP/2 flow control | QUIC flow control |
| Server push | PUSH_PROMISE | PUSH_PROMISE (simplified) |

---

## Stream Mapping (Section 6)

### Stream Types

| QUIC Stream | HTTP/3 Use |
|-------------|------------|
| Client-initiated bidirectional | Request streams (one per request/response) |
| Server-initiated bidirectional | Not used (reserved) |
| Client-initiated unidirectional | Control stream, QPACK encoder stream |
| Server-initiated unidirectional | Control stream, QPACK decoder stream, push streams |

### Required Unidirectional Streams

Each endpoint MUST create exactly:
- **One control stream** (stream type 0x00): carries SETTINGS, GOAWAY, etc.
- **One QPACK encoder stream** (stream type 0x02): sends dynamic table updates.
- **One QPACK decoder stream** (stream type 0x03): sends acknowledgments of table updates.

---

## Frame Types (Section 7)

| Type | Name | Sent On | Description |
|------|------|---------|-------------|
| 0x00 | DATA | Request streams | Carries request/response body |
| 0x01 | HEADERS | Request streams | Carries compressed header/trailer fields |
| 0x03 | CANCEL_PUSH | Control stream | Cancel a server push |
| 0x04 | SETTINGS | Control stream | Connection-level configuration |
| 0x05 | PUSH_PROMISE | Request streams | Begins a server push |
| 0x07 | GOAWAY | Control stream | Graceful shutdown signal |
| 0x0d | MAX_PUSH_ID | Control stream | Limits push IDs |

### Frame Format

```
HTTP/3 Frame {
  Type (i),        // variable-length integer
  Length (i),      // variable-length integer
  Payload (..)     // Length bytes
}
```

Note: HTTP/3 frames are **not** the same as QUIC frames. HTTP/3 frames are carried within QUIC STREAM frame payloads.

---

## Request/Response Exchange (Section 4)

### Request on a Bidirectional Stream

```
Client                              Server
  |                                   |
  |-- HEADERS (method, path, ...) --->|
  |-- DATA (request body) ----------->|
  |                                   |
  |<-- HEADERS (status, ...) ---------|
  |<-- DATA (response body) ----------|
```

- Each request/response pair uses a single client-initiated bidirectional QUIC stream.
- HEADERS frame contains QPACK-encoded pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`, `:status`).
- Streams are independent; loss on one does not affect others.

### Trailers

- A second HEADERS frame after all DATA frames carries trailer fields.
- Used for checksums, signatures, or final metadata.

---

## SETTINGS Frame (Section 7.2.4)

Sent on the control stream immediately after stream creation:

| Setting | ID | Default | Description |
|---------|----|---------|-------------|
| SETTINGS_MAX_FIELD_SECTION_SIZE | 0x06 | Unlimited | Max size of decoded header section |
| SETTINGS_QPACK_MAX_TABLE_CAPACITY | 0x01 | 0 | Max dynamic table size for QPACK |
| SETTINGS_QPACK_BLOCKED_STREAMS | 0x07 | 0 | Max streams that can be blocked on QPACK |

HTTP/2 settings (like SETTINGS_ENABLE_PUSH) are **not** valid in HTTP/3 and MUST NOT be sent.

---

## Connection Shutdown (Section 5.2)

- **GOAWAY frame**: Contains a Stream ID or Push ID indicating the last one the sender will process.
- Receiver should not initiate new requests on streams with IDs >= the indicated value.
- Allows graceful connection draining.

---

## Error Handling (Section 8)

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0100 | H3_NO_ERROR | Graceful close |
| 0x0101 | H3_GENERAL_PROTOCOL_ERROR | Generic protocol violation |
| 0x0102 | H3_INTERNAL_ERROR | Internal error |
| 0x0103 | H3_STREAM_CREATION_ERROR | Unexpected stream creation |
| 0x0104 | H3_CLOSED_CRITICAL_STREAM | Required stream was closed |
| 0x0105 | H3_FRAME_UNEXPECTED | Frame received in wrong context |
| 0x0106 | H3_FRAME_ERROR | Frame violates layout requirements |
| 0x0107 | H3_EXCESSIVE_LOAD | Peer generating excessive load |
| 0x0108 | H3_ID_ERROR | ID used incorrectly |
| 0x0109 | H3_SETTINGS_ERROR | SETTINGS frame error |
| 0x010a | H3_MISSING_SETTINGS | No SETTINGS received |
| 0x010b | H3_REQUEST_REJECTED | Request not processed |
| 0x010c | H3_REQUEST_CANCELLED | Request cancelled |
| 0x010d | H3_REQUEST_INCOMPLETE | Stream terminated prematurely |
| 0x010e | H3_MESSAGE_ERROR | Malformed message |
| 0x010f | H3_CONNECT_ERROR | CONNECT request failure |
| 0x0110 | H3_VERSION_FALLBACK | Version fallback triggered |

---

## Server Push (Section 4.6)

1. Server sends PUSH_PROMISE on a request stream (contains push ID + request headers).
2. Server sends MAX_PUSH_ID on control stream to expand push ID space.
3. Server opens a unidirectional push stream (stream type 0x01) with push ID.
4. Server sends HEADERS + DATA on the push stream.
5. Client can CANCEL_PUSH to reject.

---

## Security Considerations (Section 10)

- All HTTP/3 communication is encrypted (inherits from QUIC).
- Server push must be carefully validated; clients should not blindly cache pushed responses.
- Header compression (QPACK) has been designed to avoid CRIME/BREACH-style attacks.
- Connection coalescing: clients may reuse connections to different origins if the certificate covers them.

---

## Relevance to dart_quic

1. **Stream type detection**: First bytes of unidirectional streams indicate their type — need a dispatcher.
2. **QPACK integration**: Separate encoder/decoder streams must be managed alongside request streams.
3. **Frame parsing**: HTTP/3 frames use QUIC's variable-length integer encoding for type and length.
4. **Request/response mapping**: Each bidirectional stream maps to one `HttpRequest`/`HttpResponse` pair in Dart.
5. **Settings negotiation**: Must exchange SETTINGS before any request/response on the control stream.
6. **Graceful shutdown**: GOAWAY support needed for connection draining.
7. **Error propagation**: HTTP/3 errors map to QUIC stream/connection errors; need a unified error hierarchy.

---

## References

- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114
- RFC 9204 (QPACK): https://www.rfc-editor.org/rfc/rfc9204
- RFC 9000 (QUIC): https://www.rfc-editor.org/rfc/rfc9000
- RFC 9110 (HTTP Semantics): https://www.rfc-editor.org/rfc/rfc9110

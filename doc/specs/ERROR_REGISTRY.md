---
title: "Unified Error Code Registry"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Error Handling"
rfc_basis: []
dependencies:
  - "TESTING_SPEC.md"
---

# Unified Error Code Registry


## 1. Purpose

A fragmented error model-where QUIC transport, HTTP/3, QPACK, WebTransport, and libp2p each define their own codes-leads to inconsistent exception hierarchies and debugging pain for Dart developers. This registry unifies every error code into one reference, ensuring that the entire stack speaks a single diagnostic language.

## 2. Overview

`dart_quic` uses three disjoint code spaces. The code space is determined by the protocol layer that emits the error.

| Code Space | Range | Authority | Used By |
|------------|-------|-----------|---------|
| **QUIC Transport** | `0x00` – `0x10` and `0x0100` – `0x01ff` | RFC 9000 §20 | QUIC transport `CONNECTION_CLOSE` (type `0x1c`) |
| **HTTP/3** | `0x0100` – `0x01ff` | RFC 9114 §8.1 | HTTP/3 `CONNECTION_CLOSE` (type `0x1d`) and `RESET_STREAM` |
| **Application-defined** | `0x1000` – `0x1fff` | `dart_quic` | WebTransport sessions, libp2p multistream negotiation |

HTTP/3 reuses the same `0x0100`–`0x01ff` range as QUIC transport `CRYPTO_ERROR` values, but they are distinguished by the QUIC frame type that carries them (`0x1c` for QUIC transport errors vs. `0x1d` for application errors). In the HTTP/3 context, these values are interpreted as HTTP/3 error codes, not TLS alerts.

---





## 3. Detailed Specification

### 3.1 QUIC Transport Error Codes (RFC 9000 §20)

The following codes are used in QUIC transport-layer `CONNECTION_CLOSE` frames (type `0x1c`). They are encoded as variable-length integers.

| Code | Name | Description | Typical Trigger |
|------|------|-------------|-----------------|
| `0x00` | `NO_ERROR` | Endpoint is closing the connection without an error. | Idle timeout, clean shutdown, application-initiated close. |
| `0x01` | `INTERNAL_ERROR` | Implementation or internal error. | Unexpected invariant failure, unhandled condition. |
| `0x02` | `CONNECTION_REFUSED` | Server refuses to accept a new connection. | Server at capacity, ACL deny, version mismatch. |
| `0x03` | `FLOW_CONTROL_ERROR` | Peer violated flow-control limits. | Data or streams sent beyond current MAX_DATA / MAX_STREAMS. |
| `0x04` | `STREAM_LIMIT_ERROR` | Peer opened more streams than permitted. | New stream ID exceeds current MAX_STREAMS limit. |
| `0x05` | `FINAL_SIZE_ERROR` | Stream final size changed or was inconsistent. | RESET_STREAM or STREAM FIN final size disagreement. |
| `0x06` | `FRAME_ENCODING_ERROR` | Malformed frame; a frame type could not be parsed. | Invalid frame payload, truncated frame, unknown frame type with required semantics. |
| `0x07` | `TRANSPORT_PARAMETER_ERROR` | Invalid or absent transport parameters. | Bad values in ClientHello/EncryptedExtensions extension, missing mandatory parameter. |
| `0x08` | `CONNECTION_ID_LIMIT_ERROR` | Too many connection IDs in use. | Retired CIDs not cleared, NEW_CONNECTION_ID exceeds limit. |
| `0x09` | `PROTOCOL_VIOLATION` | Generic protocol violation not covered by a more specific code. | Any RFC 9000 rule violation (e.g., forbidden frame on control stream). |
| `0x0a` | `INVALID_TOKEN` | Invalid or unacceptable address validation token. | Retry token mismatch, expired token, invalid Initial token. |
| `0x0b` | `APPLICATION_ERROR` | Application protocol closed the connection. | HTTP/3 or WebTransport layer signals connection closure. |
| `0x0c` | `CRYPTO_BUFFER_EXCEEDED` | CRYPTO data exceeded buffer limit. | Excessive buffered handshake data without processing. |
| `0x0d` | `KEY_UPDATE_ERROR` | Fatal key update failure. | Invalid key phase update, AEAD sequence number exhaustion. |
| `0x0e` | `AEAD_LIMIT_REACHED` | AEAD integrity/confidentiality limit reached. | Packet count or byte volume exceeds AEAD safety bounds. |
| `0x0f` | `NO_VIABLE_PATH` | Connection has no usable network path. | Path validation failed on all paths, migration failed. |
| `0x10` | `CRYPTO_ERROR` | Reserved base for TLS alert codes. | See `0x0100` – `0x01ff` range below. |

#### 3.1.1 TLS Alert Mapping (`CRYPTO_ERROR`)

The range `0x0100` – `0x01ff` carries the TLS alert code in the low byte. The value `0x0100` corresponds to TLS alert `close_notify` (0x00), `0x0101` to `unexpected_message` (0x01), and so on through `0x01ff`. Alert descriptions are defined in RFC 8446 §6.2.

| Code | Mapping | Description |
|------|---------|-------------|
| `0x0100` | TLS alert `close_notify` (0x00) | Graceful TLS shutdown. |
| `0x0101` | TLS alert `unexpected_message` (0x01) | Received an inappropriate message. |
| `0x0102` | TLS alert `bad_record_mac` (0x02) | Record failed integrity check. |
| `0x0103` | TLS alert `record_overflow` (0x22) | Record exceeded allowed length. |
| `0x0104` | TLS alert `handshake_failure` (0x28) | Handshake could not complete. |
| `0x0105` | TLS alert `bad_certificate` (0x2a) | Certificate was corrupt or contained errors. |
| `0x0106` | TLS alert `unsupported_certificate` (0x2b) | Certificate type not supported. |
| `0x0107` | TLS alert `certificate_revoked` (0x2c) | Certificate revoked by issuer. |
| `0x0108` | TLS alert `certificate_expired` (0x2d) | Certificate expired or not yet valid. |
| `0x0109` | TLS alert `certificate_unknown` (0x2e) | Other certificate problem. |
| `0x010a` | TLS alert `illegal_parameter` (0x2f) | Invalid handshake parameter. |
| `0x010b` | TLS alert `unknown_ca` (0x30) | Unknown or untrusted CA. |
| `0x010c` | TLS alert `access_denied` (0x31) | Handshake refused by local policy. |
| `0x010d` | TLS alert `decode_error` (0x32) | Message could not be decoded. |
| `0x010e` | TLS alert `decrypt_error` (0x33) | Decryption or verification failure. |
| `0x010f` | TLS alert `protocol_version` (0x46) | Unsupported protocol version. |
| `0x0110` | TLS alert `insufficient_security` (0x47) | Ciphersuite/parameter too weak. |
| `0x0111` | TLS alert `internal_error` (0x50) | Internal TLS error. |
| `0x0112` | TLS alert `inappropriate_fallback` (0x56) | Inappropriate fallback attempted. |
| `0x0113` | TLS alert `missing_extension` (0x6d) | Required extension missing. |
| `0x0114` | TLS alert `unsupported_extension` (0x6e) | Unsupported extension received. |
| `0x0115` | TLS alert `unrecognized_name` (0x70) | SNI server_name not recognized. |
| `0x0116` | TLS alert `bad_certificate_status_response` (0x71) | Invalid OCSP response. |
| `0x0117` | TLS alert `bad_certificate_hash_value` (0x72) | Certificate hash mismatch. |
| `0x0118` | TLS alert `unknown_psk_identity` (0x73) | Unknown PSK identity. |
| `0x0119` – `0x01ff` | Reserved | Other TLS alert values as defined by IANA TLS Alert Registry. |

All `CRYPTO_ERROR` values are reported as `QuicHandshakeException` in the Dart API unless a QUIC `CONNECTION_CLOSE` (type `0x1c`) is received with one of these codes, in which case the transport layer emits a `QuicConnectionException`.

---


### 3.2 HTTP/3 Error Codes (RFC 9114 §8.1)

The following codes are used in HTTP/3 `CONNECTION_CLOSE` (type `0x1d`) and `RESET_STREAM` frames. They are also encoded as variable-length integers.

| Code | Name | Description | Typical Trigger |
|------|------|-------------|-----------------|
| `0x0100` | `H3_NO_ERROR` | Clean HTTP/3 close. | Graceful GOAWAY or user-initiated shutdown. |
| `0x0101` | `H3_GENERAL_PROTOCOL_ERROR` | Unspecified HTTP/3 protocol violation. | Any HTTP/3 rule violation without a specific code. |
| `0x0102` | `H3_INTERNAL_ERROR` | Implementation error in the HTTP/3 layer. | Internal invariant failure, unexpected parser state. |
| `0x0103` | `H3_STREAM_CREATION_ERROR` | Peer created a stream of an unexpected type. | Wrong unidirectional stream type, request stream from server. |
| `0x0104` | `H3_CLOSED_CRITICAL_STREAM` | A critical stream (control/QPACK) was closed. | Control, encoder, or decoder stream reset. |
| `0x0105` | `H3_FRAME_UNEXPECTED` | Frame received in a disallowed context. | SETTINGS on request stream, DATA on control stream. |
| `0x0106` | `H3_FRAME_ERROR` | Malformed frame. | Truncated frame, invalid varint, duplicate setting. |
| `0x0107` | `H3_EXCESSIVE_LOAD` | Peer generating excessive load. | Too many requests, too much header data. |
| `0x0108` | `H3_ID_ERROR` | Invalid or malformed stream/push ID. | Push ID reused, stream ID out of order. |
| `0x0109` | `H3_SETTINGS_ERROR` | Invalid SETTINGS frame or value. | Duplicate identifier, value out of range, unknown mandatory setting. |
| `0x010a` | `H3_MISSING_SETTINGS` | SETTINGS frame not received as first frame. | Non-SETTINGS frame on control stream before SETTINGS. |
| `0x010b` | `H3_REQUEST_REJECTED` | Server rejected request without processing. | Server policy, overload. |
| `0x010c` | `H3_REQUEST_CANCELLED` | Request cancelled before response. | Application cancellation. |
| `0x010d` | `H3_REQUEST_INCOMPLETE` | Stream ended before complete request. | Missing required headers, truncated body. |
| `0x010e` | `H3_MESSAGE_ERROR` | Malformed HTTP message. | Invalid pseudo-headers, duplicate Content-Length, forbidden header. |
| `0x010f` | `H3_CONNECT_ERROR` | CONNECT or CONNECT-derived request failed. | WebTransport/extended CONNECT setup failed. |
| `0x0110` | `H3_VERSION_FALLBACK` | Server requested client fall back to HTTP/2 or HTTP/1.1. | Alt-Svc or equivalent negotiation signal. |

#### 3.2.1 QPACK Error Codes (RFC 9204 §3)

| Code | Name | Description | Typical Trigger |
|------|------|-------------|-----------------|
| `0x0200` | `QPACK_DECOMPRESSION_FAILED` | Failed to decompress a field section. | Invalid encoded field section, bad static/dynamic index. |
| `0x0201` | `QPACK_ENCODER_STREAM_ERROR` | Invalid instruction on the QPACK encoder stream. | Unknown instruction, invalid dynamic table index. |

`QPACK_DECOMPRESSION_FAILED` closes the connection. `QPACK_ENCODER_STREAM_ERROR` closes the connection because the encoder stream is critical to header decoding.

---


### 3.3 Application Error Codes (dart_quic Defined)

The range `0x1000` – `0x1fff` is reserved for `dart_quic` application-layer protocols. It is divided into two sub-ranges: WebTransport session errors and libp2p protocol negotiation errors.

#### 3.3.1 WebTransport Session Errors

These codes are used in WebTransport `WT_CLOSE_SESSION` capsules and in QUIC `RESET_STREAM`/`STOP_SENDING` frames for WebTransport streams.

| Code | Name | Description | Typical Trigger |
|------|------|-------------|-----------------|
| `0x1000` | `WTAPP_NO_ERROR` | Clean WebTransport session close. | `session.close()` without error. |
| `0x1001` | `WTAPP_SESSION_FAILED` | Generic session establishment failure. | CONNECT handshake rejected, missing required SETTINGS. |
| `0x1002` | `WTAPP_SESSION_GONE` | Session terminated; streams are being torn down. | Remote reset or `WT_CLOSE_SESSION` received. |
| `0x1003` | `WTAPP_UNREACHABLE` | Peer could not be reached or resolved. | DNS failure, routing failure. |
| `0x1004` | `WTAPP_UNACCEPTABLE_ANSWER` | CONNECT response rejected the session. | Non-2xx response status, missing `:protocol`. |
| `0x1005` | `WTAPP_REQUEST_REJECTED` | Server explicitly rejected the WebTransport request. | Server policy, resource limit. |
| `0x1006` | `WTAPP_FLOW_CONTROL_ERROR` | WebTransport flow-control limit violated. | Per-session data or stream limit exceeded. |
| `0x1007` – `0x10ff` | Reserved | Reserved for future WebTransport application errors. | — |

> **Note:** The wire-format WebTransport capsule codes (`0x2843`, `0x170d7b68`, `0x045d4487`, etc.) defined in [WEBTRANSPORT_SPEC.md](WEBTRANSPORT_SPEC.md) are **capsule type identifiers**, not application error codes. They are listed in this registry only for cross-reference and MUST NOT be used as QUIC `CONNECTION_CLOSE` error codes.

#### 3.3.2 libp2p Protocol Negotiation Errors

These codes are used in the libp2p QUIC adapter, primarily during multistream-select protocol negotiation on a QUIC stream.

| Code | Name | Description | Typical Trigger |
|------|------|-------------|-----------------|
| `0x1100` | `LP2P_NO_COMMON_PROTOCOL` | No protocol supported by both peers. | Multistream-select `na` to all proposed protocols. |
| `0x1101` | `LP2P_PROTOCOL_NOT_SUPPORTED` | Locally requested protocol is not supported. | Peer selected a protocol not registered locally. |
| `0x1102` | `LP2P_SECURITY_UPGRADE_FAILED` | TLS 1.3 peer authentication failed. | Invalid libp2p self-signed certificate, peer ID mismatch. |
| `0x1103` | `LP2P_EARLY_DATA_REJECTED` | 0-RTT / early data rejected. | Peer does not accept resumed early data. |
| `0x1104` | `LP2P_STREAM_RESET` | Stream reset by libp2p protocol layer. | Protocol handler reset stream. |
| `0x1105` | `LP2P_MULTISTREAM_PROTOCOL_ERROR` | multistream-select protocol violation. | Invalid `/multistream/` line, unexpected message. |
| `0x1106` – `0x11ff` | Reserved | Reserved for future libp2p application errors. | — |
| `0x1200` – `0x1fff` | Reserved | Reserved for future `dart_quic` application-layer definitions. | — |

---


### 3.4 Dart API Error Mapping

The following table maps wire error codes to the Dart exception classes defined in [DART_API_SPEC.md](DART_API_SPEC.md) §6. The transport layer is responsible for choosing the correct exception class based on the frame type, the protocol layer, and whether the error is connection-level or stream-level.

| Error Code(s) | Dart Exception Class | When Thrown |
|---------------|----------------------|-------------|
| `0x00` (`NO_ERROR`) | `QuicConnectionException` | Clean connection close; `errorCode` is `0` and `reason` may be present. |
| `0x01` – `0x10` (transport) | `QuicConnectionException` | Any QUIC transport `CONNECTION_CLOSE` (type `0x1c`). |
| `0x0100` – `0x01ff` (transport) | `QuicHandshakeException` | TLS alert surfaced during handshake. |
| `0x0100` – `0x01ff` (HTTP/3) | `Http3ProtocolException` | HTTP/3 `CONNECTION_CLOSE` (type `0x1d`). |
| `0x0200` – `0x0201` | `Http3ProtocolException` | QPACK decompression or encoder stream error. |
| `0x1000` – `0x10ff` | `WebTransportException` | WebTransport session close or stream reset. |
| `0x1100` – `0x11ff` | `QuicStreamException` | libp2p protocol negotiation failure on a stream. |
| `0x1200` – `0x1fff` | `QuicConnectionException` or `QuicStreamException` | Other application-layer errors, depending on scope. |

For stream-level errors (`RESET_STREAM` or `STOP_SENDING`), the implementation emits `QuicStreamException` (or `Http3StreamException` for HTTP/3 request streams) and sets the `errorCode` field to the value from the wire. For connection-level errors, it emits `QuicConnectionException` with `isApplicationError` set to `true` for application `CONNECTION_CLOSE` (type `0x1d`) and `false` for transport `CONNECTION_CLOSE` (type `0x1c`).

---



## 4. Acceptance Criteria

- [ ] All QUIC transport error codes from `0x00` to `0x10` are defined as constants in the implementation.
- [ ] All `CRYPTO_ERROR` values in `0x0100` – `0x01ff` are recognized and mapped to TLS alert descriptions.
- [ ] All HTTP/3 error codes from RFC 9114 §8.1 are defined as constants.
- [ ] All QPACK error codes from RFC 9204 §3 are defined as constants.
- [ ] All `dart_quic` application error codes in `0x1000` – `0x1fff` are defined and documented.
- [ ] The Dart API error mapping table is implemented consistently with [DART_API_SPEC.md](DART_API_SPEC.md).
- [ ] No error code from a private or experimental range is emitted without explicit documentation.
- [ ] `CONNECTION_CLOSE` reason phrases are sanitized before logging (see §5 Security Considerations).

---





## 5. Security Considerations

- **Do not leak internal state via error codes.** Error codes sent to the peer MUST be chosen from the public registry. Internal implementation details, stack traces, or file paths MUST NOT appear in `CONNECTION_CLOSE` reason phrases or application error messages.
- **Reason phrase sanitization.** Any UTF-8 reason phrase received from the network MUST be validated for length and encoding. Logged reason phrases MUST be truncated and stripped of control characters to prevent log injection.
- **Avoid oracle attacks.** Sending different error codes for similar failures (e.g., distinguishing "invalid token" from "bad certificate") can leak information to attackers. Prefer the most generic applicable code unless the distinction is required by the protocol.
- **Rate limiting.** Repetitive `CONNECTION_CLOSE` emissions triggered by malformed input MUST be rate-limited to avoid amplification.
- **QPACK dynamic table isolation.** Header compression errors MUST NOT expose the dynamic table contents in error messages.

---





## 6. Dependencies

- [DART_API_SPEC.md](DART_API_SPEC.md): Defines the exception hierarchy and error propagation rules.
- [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md): Defines `CONNECTION_CLOSE` frame types `0x1c` and `0x1d` and variable-length integer encoding.
- [QUIC_STREAMS_SPEC.md](QUIC_STREAMS_SPEC.md): Defines stream reset and `STOP_SENDING` semantics.
- [HTTP3_SPEC.md](HTTP3_SPEC.md): Defines HTTP/3 frame usage and stream mapping.
- [WEBTRANSPORT_SPEC.md](WEBTRANSPORT_SPEC.md): Defines WebTransport capsule types and session lifecycle.
- [LIBP2P_QUIC_SPEC.md](LIBP2P_QUIC_SPEC.md): Defines libp2p multistream-select integration over QUIC.

---















## Used By

- [TESTING_SPEC.md](TESTING_SPEC.md) — Error registry is tested through the testing spec.
## 7. Testing Strategy

- **Unit tests:** Verify each error code constant is defined, has the correct integer value, and round-trips through variable-length integer encoding.
- **Frame tests:** Encode/decode `CONNECTION_CLOSE` and `RESET_STREAM` frames containing every error code in this registry.
- **Mapping tests:** Assert that receiving a given error code on the correct frame type produces the expected Dart exception class.
- **Interop tests:** Exchange error conditions with `quic-go`, `aioquic`, and `h3spec` to confirm code interpretation.
- **Security tests:** Verify reason phrases are sanitized, internal errors are mapped to `INTERNAL_ERROR` (0x01), and no stack traces are exposed.
- **Fuzz tests:** Use malformed error codes and frame payloads to ensure the parser closes the connection with `FRAME_ENCODING_ERROR` (0x06) or `PROTOCOL_VIOLATION` (0x09) instead of crashing.

---





## 8. References

- RFC 9000, §20: *QUIC Error Codes* — https://www.rfc-editor.org/rfc/rfc9000#section-20
- RFC 9114, §8.1: *HTTP/3 Error Codes* — https://www.rfc-editor.org/rfc/rfc9114#section-8.1
- RFC 9204, §3: *QPACK Error Codes* — https://www.rfc-editor.org/rfc/rfc9204#section-3
- RFC 8446, §6.2: *Alert Protocol* — https://www.rfc-editor.org/rfc/rfc8446#section-6.2
- [DART_API_SPEC.md](DART_API_SPEC.md): Dart exception hierarchy
- [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md): Wire encoding of error-carrying frames
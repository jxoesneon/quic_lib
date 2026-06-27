---
title: "QUIC Transport Parameters Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Transport Parameters"
rfc_basis:
  - "RFC 9000 Section 18"
dependencies:
  - "QUIC_WIRE_SPEC.md"
  - "QUIC_CRYPTO_SPEC.md"
  - "HTTP3_SPEC.md"
  - "ROADMAP.md"
  - "ERROR_REGISTRY.md"
---

# QUIC Transport Parameters Specification

## 1. Purpose

Transport parameters are the primary mechanism for negotiating connection behavior; a canonical spec prevents interop failures. Without precise agreement on which parameters are sent, how they are encoded, and what values are legal, peers will mis-negotiate flow-control windows, idle timeouts, and extension support. This document defines the wire format, semantics, validation rules, and Dart API surface for QUIC transport parameters in `dart_quic`.

## 2. Overview

Transport parameters are exchanged during the TLS handshake as a QUIC extension (RFC 9000 Section 18, RFC 9001 Section 8.2). They are encoded as a list of `(parameter_id, length, value)` tuples, each parameter identified by a variable-length integer codepoint. The parameter list is carried inside the `quic_transport_parameters` TLS extension in ClientHello and EncryptedExtensions messages.

```
TransportParameters {
  Parameter (..) * N
}
```

Each parameter:
- Has a unique `parameter_id` (varint).
- Has a `length` (varint) indicating the size of the value.
- Has a `value` (exactly `length` bytes).

Unknown parameters MUST be ignored. Duplicate parameters are a protocol violation.

## 3. Parameter List

| Parameter Name | ID (hex) | Type | Default | Description |
|----------------|----------|------|---------|-------------|
| `original_destination_connection_id` | `0x00` | Connection ID | absent | The DCID from the client's first Initial packet; server-only. |
| `max_idle_timeout` | `0x01` | varint (ms) | `0` | Idle timeout in milliseconds; `0` disables. |
| `stateless_reset_token` | `0x02` | 16-byte token | absent | Token used to validate stateless resets; server-only. |
| `max_udp_payload_size` | `0x03` | varint (bytes) | `65527` | Maximum UDP payload size; MUST be >= 1200. |
| `initial_max_data` | `0x04` | varint (bytes) | `0` | Initial connection-level flow-control limit. |
| `initial_max_stream_data_bidi_local` | `0x05` | varint (bytes) | `0` | Initial stream-level limit for locally-initiated bidi streams. |
| `initial_max_stream_data_bidi_remote` | `0x06` | varint (bytes) | `0` | Initial stream-level limit for remotely-initiated bidi streams. |
| `initial_max_stream_data_uni` | `0x07` | varint (bytes) | `0` | Initial stream-level limit for uni streams. |
| `initial_max_streams_bidi` | `0x08` | varint (count) | `0` | Initial cumulative bidi stream limit. |
| `initial_max_streams_uni` | `0x09` | varint (count) | `0` | Initial cumulative uni stream limit. |
| `ack_delay_exponent` | `0x0a` | varint | `3` | Scaling factor for ACK Delay field; MUST be <= 20. |
| `max_ack_delay` | `0x0b` | varint (ms) | `25` | Maximum ACK delay; MUST be <= 2^14. |
| `disable_active_migration` | `0x0c` | flag (0 bytes) | absent | If present, sender disables active connection migration. |
| `preferred_address` | `0x0d` | struct | absent | Server's preferred address for migration; server-only. |
| `active_connection_id_limit` | `0x0e` | varint | `2` | Maximum connection IDs the peer can issue; MUST be >= 2. |
| `initial_source_connection_id` | `0x0f` | Connection ID | absent | The SCID the endpoint used in its first Initial packet. |
| `retry_source_connection_id` | `0x10` | Connection ID | absent | The SCID from the Retry packet; server-only, if Retry was used. |
| `max_datagram_frame_size` | `0x20` | varint (bytes) | `0` | Maximum DATAGRAM frame payload size (RFC 9221); `0` or absent disables datagrams. |
| `h3_settings` | *see HTTP3_SPEC.md* | varint pairs | absent | HTTP/3 SETTINGS equivalent exposed as a transport parameter for pre-negotiation; exact codepoint and encoding defined in [HTTP3_SPEC.md](HTTP3_SPEC.md). |

### 3.1 Server-Only Parameters

The following parameters MUST NOT be sent by a client:

- `original_destination_connection_id` (`0x00`)
- `stateless_reset_token` (`0x02`)
- `preferred_address` (`0x0d`)
- `retry_source_connection_id` (`0x10`)

A client that receives any of these from a server MUST process them normally. A server that receives any of these from a client MUST close the connection with `TRANSPORT_PARAMETER_ERROR` (see [ERROR_REGISTRY.md](ERROR_REGISTRY.md)).

## 4. Encoding Format

Each parameter is encoded as:

```
TransportParameter {
  Parameter ID (i),
  Parameter Length (i),
  Parameter Value (..)
}
```

- `Parameter ID`: variable-length integer (see [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md) §2.1).
- `Parameter Length`: variable-length integer indicating the number of bytes in `Parameter Value`.
- `Parameter Value`: opaque byte sequence of exactly `Parameter Length` bytes.

### 4.1 Constraints

- **No duplicates**: A given `Parameter ID` MUST appear at most once in the transport parameters extension. Duplicate IDs are a protocol violation and MUST result in connection close with `TRANSPORT_PARAMETER_ERROR`.
- **Unknown parameters**: Endpoints MUST ignore parameters with unrecognized IDs.
- **Zero-length values**: Some parameters (e.g., `disable_active_migration`) have a zero-length value; their presence alone signals a boolean `true`.

## 5. Validation Rules

1. **Client/server directionality**: A client MUST NOT send server-only parameters. A server MAY send any defined parameter.
2. **Minimum `max_udp_payload_size`**: If present, MUST be at least `1200`. Values below `1200` MUST trigger `TRANSPORT_PARAMETER_ERROR`.
3. **`ack_delay_exponent` bound**: MUST be `<= 20`. Values above `20` MUST trigger `TRANSPORT_PARAMETER_ERROR`.
4. **`max_ack_delay` bound**: MUST be `<= 16384` (2^14). Values above this MUST trigger `TRANSPORT_PARAMETER_ERROR`.
5. **`active_connection_id_limit` bound**: MUST be at least `2`. Values below `2` MUST trigger `TRANSPORT_PARAMETER_ERROR`.
6. **`initial_source_connection_id` presence**: Endpoints MUST send this parameter. Absence is a protocol violation.
7. **Retry consistency**: If the server sent a Retry packet, it MUST include `retry_source_connection_id`. If no Retry was performed, it MUST NOT include this parameter.
8. **Original DCID consistency**: The value of `original_destination_connection_id` MUST match the DCID from the client's first Initial packet.
9. **Source DCID consistency**: The value of `initial_source_connection_id` MUST match the SCID the endpoint used in its first Initial packet.
10. **`initial_max_data` consistency**: MUST be greater than or equal to each of the `initial_max_stream_data_*` parameters. Violation MAY be treated as a protocol error or logged as a warning at implementer discretion.

## 6. Default Values

| Parameter | Default Value | Semantics |
|-----------|---------------|-----------|
| `max_idle_timeout` | `0` | No idle timeout. |
| `max_udp_payload_size` | `65527` | Maximum permitted UDP payload. |
| `initial_max_data` | `0` | No initial connection credit. |
| `initial_max_stream_data_bidi_local` | `0` | No initial bidi-local stream credit. |
| `initial_max_stream_data_bidi_remote` | `0` | No initial bidi-remote stream credit. |
| `initial_max_stream_data_uni` | `0` | No initial uni stream credit. |
| `initial_max_streams_bidi` | `0` | No bidi streams allowed initially. |
| `initial_max_streams_uni` | `0` | No uni streams allowed initially. |
| `ack_delay_exponent` | `3` | ACK delay scaled by 2^3 = 8. |
| `max_ack_delay` | `25` | Up to 25 ms of delayed ACKs. |
| `disable_active_migration` | absent | Active migration is allowed. |
| `active_connection_id_limit` | `2` | Peer may issue up to 2 CIDs. |
| `max_datagram_frame_size` | `0` | Datagram extension disabled. |

## 7. Dart API

This API extends the configuration surface defined in [DART_API_SPEC.md](DART_API_SPEC.md) §2.2 and §2.3.4.

```dart
/// Represents the set of QUIC transport parameters exchanged during the handshake.
/// Maps 1:1 to the wire encoding defined in Section 4.
abstract class TransportParameters {
  /// Encode the full parameter list to wire bytes.
  List<int> toBytes();

  /// Decode a parameter list from wire bytes.
  /// Throws [QuicTransportParameterException] on duplicate IDs, invalid values,
  /// or missing mandatory parameters.
  static TransportParameters fromBytes(List<int> bytes);

  /// Validate all parameters according to Section 5.
  /// Returns a list of validation errors; empty list means valid.
  List<TransportParameterError> validate({required bool isClient});
}

/// Individual parameter entry.
class TransportParameter {
  final int id;       // parameter codepoint
  final List<int> value; // raw bytes (may be empty)
}

/// Validation error record.
class TransportParameterError {
  final int? parameterId;
  final String message;
}
```

### 7.1 Integration with QuicConfiguration

`QuicConfiguration` ([DART_API_SPEC.md](DART_API_SPEC.md) §2.3.4) produces a `TransportParameters` instance for the handshake, and the peer's received `TransportParameters` update the connection's runtime limits (flow control, idle timeout, datagram support, etc.).

## 8. Acceptance Criteria

- [ ] All 17 RFC 9000 parameters and `max_datagram_frame_size` round-trip through `toBytes` / `fromBytes`.
- [ ] Duplicate parameter IDs are rejected with `TRANSPORT_PARAMETER_ERROR`.
- [ ] Unknown parameter IDs are silently ignored.
- [ ] Server-only parameters sent by a client are rejected.
- [ ] `max_udp_payload_size` < 1200, `ack_delay_exponent` > 20, and `active_connection_id_limit` < 2 are each rejected.
- [ ] Missing `initial_source_connection_id` is rejected.

## 9. Security Considerations

- **Parameter flooding**: A malicious peer could send an extremely large number of transport parameters to exhaust parser memory. Implementations MUST limit the total size of the transport parameters extension (recommended max: 64 KB) and reject oversized extensions.
- **Oversized values**: Parameters like `initial_max_data` or `max_udp_payload_size` with unreasonably large values could cause integer overflows or excessive memory allocation. The Dart API MUST use fixed-width integers (`int` in Dart is 64-bit signed) and validate bounds before allocation.
- **Downgrade by removing `max_udp_payload_size`**: An on-path attacker cannot remove transport parameters because they are authenticated by the TLS handshake. However, a buggy implementation that ignores the parameter and falls back to 1200-byte packets could be manipulated into suboptimal performance. Implementations MUST honor the peer's advertised `max_udp_payload_size` after handshake completion.
- **Stateless reset token integrity**: The `stateless_reset_token` is a 128-bit secret. If exposed or predictable, an attacker can inject fake stateless reset packets and terminate connections. It MUST be generated with a cryptographically secure random source and MUST NOT be logged or transmitted outside the handshake.
- **Preferred address spoofing**: The `preferred_address` parameter allows a server to redirect a client to a new address. Clients MUST validate the new address via path validation (RFC 9000 Section 9) before sending non-probing frames.

## 10. References

- [RFC 9000 Section 18](https://tools.ietf.org/html/rfc9000#section-18) — Transport Parameter Encoding
- [RFC 9001 Section 8.2](https://tools.ietf.org/html/rfc9001#section-8.2) — QUIC Transport Parameters Extension
- [RFC 9221](https://tools.ietf.org/html/rfc9221) — QUIC Datagrams (`max_datagram_frame_size`)
- [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md) — Variable-length integer encoding and frame formats
- [QUIC_CRYPTO_SPEC.md](QUIC_CRYPTO_SPEC.md) — TLS handshake integration
- [HTTP3_SPEC.md](HTTP3_SPEC.md) — HTTP/3 SETTINGS and stream mapping
- [DART_API_SPEC.md](DART_API_SPEC.md) — Public Dart API contract
- [ERROR_REGISTRY.md](ERROR_REGISTRY.md) — `TRANSPORT_PARAMETER_ERROR` and other error codes

## 11. Used By

- [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md) — Frame parsing and varint encoding.
- [QUIC_CRYPTO_SPEC.md](QUIC_CRYPTO_SPEC.md) — TLS handshake integration (transport parameters extension).
- [HTTP3_SPEC.md](HTTP3_SPEC.md) — HTTP/3 SETTINGS pre-negotiation via `h3_settings` parameter.
- [ROADMAP.md](ROADMAP.md) — Milestone 1.3 (TLS integration) and 1.5 (flow control limits).
- [DART_API_SPEC.md](DART_API_SPEC.md) — `QuicConfiguration` and `TransportParameters` class.

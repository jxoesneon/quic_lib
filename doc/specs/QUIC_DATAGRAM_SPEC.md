---
title: "QUIC Datagram Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Datagram Extension"
rfc_basis: []
dependencies:
  - "ROADMAP.md"
  - "WEBTRANSPORT_SPEC.md"
---

# QUIC Datagram Specification


## 1. Purpose

Real-time applications-gaming, DNS-over-QUIC, live media-need unreliable, low-latency messaging that QUIC streams cannot provide because of head-of-line blocking and retransmission. The QUIC Datagram extension fills this gap without abandoning the connection encryption and congestion control, giving dart_quic a complete transport portfolio.

## 2. Overview

QUIC Datagrams provide an unreliable message abstraction on top of a QUIC connection. Each datagram is carried in one or more QUIC DATAGRAM frames. Unlike QUIC streams, datagrams are not retransmitted, not ordered, and not subject to QUIC flow control. They are still subject to congestion control and cannot be larger than the negotiated `max_datagram_frame_size`.

```
┌─────────────────────────────┐
│       Application           │  // DNS, game, media
├─────────────────────────────┤
│    QUIC Datagram API        │  // sendDatagram / receiveDatagram
├─────────────────────────────┤
│     DATAGRAM frame (0x30/31)│
├─────────────────────────────┤
│     QUIC Packet / Short Hdr │
├─────────────────────────────┤
│         UDP Datagram        │
└─────────────────────────────┘
```

---





## 3. Detailed Specification

### 3.1 DATAGRAM Frame Format

DATAGRAM frames use frame types `0x30` and `0x31` (RFC 9221 Section 4).

```
DATAGRAM Frame {
  Type (i) = 0x30 or 0x31,
  [Length (i),]            // only if Type == 0x31
  Datagram Data (..)
}
```

- Type `0x30`: The remainder of the QUIC packet payload after the Type field is the datagram data.
- Type `0x31`: A `Length` field precedes the data; `Length` is a variable-length integer.
- Either endpoint MAY send the length-bearing variant (`0x31`). Receivers MUST parse both.
- A DATAGRAM frame MUST NOT be split across multiple QUIC packets, but multiple DATAGRAM frames MAY appear in a single packet.
- The frame is encoded/decoded by the wire codec as an ordinary QUIC frame type.


### 3.2 Transport Parameter

| Parameter | Codepoint | Semantics |
|-----------|-----------|-----------|
| `max_datagram_frame_size` | `0x0020` (decimal 32) | Maximum size of a DATAGRAM frame payload this endpoint is willing to receive, in bytes. A value of `0` or absence means the endpoint does not support QUIC datagrams. |

- The parameter is a variable-length integer.
- The value is the maximum size of the **Datagram Data** field, not the UDP payload.


### 3.3 Negotiation

Both endpoints MUST advertise `max_datagram_frame_size` during the QUIC handshake for QUIC datagrams to be enabled:

1. If both endpoints receive a non-zero value from the peer, the extension is **enabled** for the connection.
2. If either endpoint omits the parameter or sends `0`, the extension is **disabled**; endpoints MUST NOT send DATAGRAM frames on this connection.
3. An endpoint MUST NOT send DATAGRAM frames larger than the peer's advertised `max_datagram_frame_size`.


### 3.4 Service Properties

QUIC Datagrams have the following transport semantics:

- **No retransmission**: A DATAGRAM frame is not acknowledged, retransmitted, or recoverable by the sender. The application may choose its own reliability scheme.
- **No ordering guarantees**: Datagrams may arrive out of order or be dropped independently.
- **No flow control**: DATAGRAM frames do not consume stream or connection flow-control credit and are not limited by `MAX_DATA` / `MAX_STREAM_DATA`.
- **Congestion controlled**: DATAGRAM frames count toward `bytes_in_flight` and MUST respect the congestion controller's `can_send` window. A datagram that cannot be sent due to congestion MUST be dropped or buffered according to application policy, not injected into the network.


### 3.5 Maximum Payload Size

The maximum payload an application can place in a single DATAGRAM frame is limited by both the peer's `max_datagram_frame_size` and the path MTU:

```
max_datagram_payload = min(
    max_datagram_frame_size,
    max_packet_size - quic_packet_overhead
)
```

Where:

- `max_datagram_frame_size`: value advertised by the receiver (peer).
- `max_packet_size`: current maximum QUIC packet size (path MTU / DPLPMTUD result, typically 1200 bytes during handshake).
- `quic_packet_overhead`: short header, packet number, encryption/authentication tag, and any other frames in the packet.

An application datagram larger than the maximum payload MUST be either fragmented by the application or rejected with an error.


### 3.6 Relationship with QUIC Connection Lifecycle

- DATAGRAM frames may be sent once the handshake completes and the extension is negotiated.
- An endpoint MUST NOT send DATAGRAM frames after it has initiated connection closure (sent `CONNECTION_CLOSE` or received a fatal error) or after the connection has been closed.
- DATAGRAM frames received in the final flight before a connection closes are valid but may be silently discarded if the connection is already tearing down.
- DATAGRAM frames are not associated with any stream; closure of a stream does not affect datagrams.

---



## 4. Acceptance Criteria

- [ ] DATAGRAM frames `0x30` (no length) parse and serialize correctly.
- [ ] DATAGRAM frames `0x31` (with length) parse and serialize correctly.
- [ ] Transport parameter `max_datagram_frame_size` (`0x20`) is sent with a non-zero value when enabled.
- [ ] Extension is disabled if either endpoint omits `max_datagram_frame_size` or sends zero.
- [ ] Sender does not emit DATAGRAM frames larger than the peer's advertised `max_datagram_frame_size`.
- [ ] Sender does not emit DATAGRAM frames larger than the current packet size allows.
- [ ] DATAGRAM frames are not retransmitted after packet loss.
- [ ] DATAGRAM frames are not ordered by the receiver and are delivered as soon as decrypted.
- [ ] DATAGRAM frames do not consume QUIC flow-control credit.
- [ ] Congestion controller counts DATAGRAM frame bytes in `bytes_in_flight`.
- [ ] DATAGRAM sending is blocked when congestion window is exhausted.
- [ ] DATAGRAM frames are no longer sent after connection closure begins.

---





## 5. Security Considerations

- **Amplification**: Because DATAGRAM frames are not acknowledged, implementations must not allow them to bypass QUIC's anti-amplification limits (RFC 9000 Section 8.1). The endpoint must track received bytes before sending datagrams, especially during handshake.
- **Congestion control enforcement**: Bypassing congestion control for DATAGRAM frames would allow network abuse and starvation of stream traffic. The congestion controller MUST account for every DATAGRAM frame byte in `bytes_in_flight`.
- **No replay**: DATAGRAM frames are protected by the same QUIC packet encryption and packet-number space as the enclosing packet; the implementation MUST NOT decrypt or accept datagrams from an invalid packet number or key phase.
- **Size enforcement**: Receiving a DATAGRAM frame larger than the advertised `max_datagram_frame_size` is a protocol violation and MUST result in connection close with error code `PROTOCOL_VIOLATION` (RFC 9000 Section 10.2).

---





## 6. Dependencies

- [QUIC_WIRE_SPEC.md](QUIC_WIRE_SPEC.md): Frame parsing/serialization for variable-length integers and frame types.
- [QUIC_STREAMS_SPEC.md](QUIC_STREAMS_SPEC.md): Contrast with stream semantics; connection flow control is shared infrastructure but datagrams do not consume stream credit.
- [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md): Congestion control and `bytes_in_flight` accounting.

---















## Used By

- [ROADMAP.md](ROADMAP.md) — QUIC Datagram extension is part of the transport layer roadmap.
- [WEBTRANSPORT_SPEC.md](WEBTRANSPORT_SPEC.md) — WebTransport may use QUIC datagrams for unreliable messaging.
## 7. Testing Strategy

- Unit tests for `0x30` and `0x31` frame encode/decode round-trips.
- Transport parameter negotiation tests: both present, one absent, one zero, oversized value.
- Sender policy tests: refuse to send datagrams when disabled, drop oversized datagrams.
- Congestion-control tests: verify DATAGRAM bytes are counted and limited by the congestion window.
- Loss simulation: verify lost DATAGRAM frames are never retransmitted.
- Interop: exchange DATAGRAM frames with `quic-go`, `aioquic`, and `ngtcp2` peers.
- DNS-over-QUIC (RFC 9250) scenario: carry DNS queries/responses in DATAGRAM frames.
- Edge cases: zero-length datagrams, maximum-size datagrams, multiple datagrams in one packet.

---





## 8. References

- RFC 9221 (An Unreliable Datagram Extension to QUIC): https://www.rfc-editor.org/rfc/rfc9221
- RFC 9000 (QUIC: A UDP-Based Multiplexed and Secure Transport): https://www.rfc-editor.org/rfc/rfc9000
- RFC 9250 (DNS over Dedicated QUIC Connections): https://www.rfc-editor.org/rfc/rfc9250
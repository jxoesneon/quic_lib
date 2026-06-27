---
title: "RFC 9000 Notes: QUIC: A UDP-Based Multiplexed and Secure Transport"
category: research
authors: "J. Iyengar (Ed.), M. Thomson (Ed.)"
published: "May 2021"
companion_rfcs:
  - "9001 (TLS), 9002 (Recovery), 8999 (Invariants)"
---

# RFC 9000 Notes: QUIC: A UDP-Based Multiplexed and Secure Transport



## 1. Purpose

RFC 9000 is a dense, 150-page specification that every implementer must internalize. These notes distill the core concepts-packet structure, stream types, connection lifecycle, migration, and transport parameters-into a quick-reference format that keeps the dart_quic team aligned without requiring constant re-reading of the full RFC.

## 2. Abstract

RFC 9000 defines the core QUIC transport protocol. QUIC provides applications with flow-controlled streams for structured communication, low-latency connection establishment, and network path migration. It includes security measures ensuring confidentiality, integrity, and availability.

---


## 3. Key Design Principles

1. **UDP substrate**: QUIC packets are carried in UDP datagrams to facilitate deployment through existing NATs and middleboxes.
2. **Encryption by default**: The entirety of each packet is authenticated; nearly all content is encrypted. Only the invariant header fields (flags, version, connection IDs) are visible to on-path elements.
3. **Stream multiplexing without head-of-line blocking**: Unlike TCP+TLS+HTTP/2, loss in one stream does not block others.
4. **Connection migration**: Connections are identified by Connection IDs, not 4-tuples, enabling seamless migration across network changes.
5. **Low-latency handshake**: 1-RTT for new connections; 0-RTT for resumed connections.

---


## 4. Packet Structure

### Header Types

| Header Type | Use Case | Key Properties |
|-------------|----------|----------------|
| **Long Header** | Handshake packets (Initial, Handshake, 0-RTT, Retry) | Contains Version, DCID Len, DCID, SCID Len, SCID |
| **Short Header** | Post-handshake (1-RTT) | Contains only DCID; minimal overhead |

### Variable-Length Integer Encoding (Section 16)

QUIC uses a variable-length integer encoding for most numeric values. See [QUIC_WIRE_SPEC.md §2](../specs/QUIC_WIRE_SPEC.md#2-variable-length-integer-encoding-rfc-9000-section-16) for the canonical encoding table.

### Packet Types (Long Header)

See [QUIC_WIRE_SPEC.md §3](../specs/QUIC_WIRE_SPEC.md#3-packet-types-and-headers-rfc-9000-section-17) for the complete packet type reference. The four long-header types are Initial, 0-RTT, Handshake, and Retry.

---


## 5. Frame Types (Section 12.4)

RFC 9000 defines 19 frame types for connection management, flow control, stream data, and path validation. See [QUIC_WIRE_SPEC.md §4](../specs/QUIC_WIRE_SPEC.md#4-frame-types-and-formats-rfc-9000-section-19) for the complete frame type reference and wire encoding details. |

---


## 6. Connection Lifecycle

### Handshake (Section 7)

```
Client                                    Server
  |                                         |
  |--- Initial[CRYPTO(ClientHello)] ------->|
  |                                         |
  |<-- Initial[CRYPTO(ServerHello)] --------|
  |<-- Handshake[CRYPTO(EncExts,Cert,CV,Fin)] --|
  |                                         |
  |--- Handshake[CRYPTO(Fin)] ------------->|
  |--- 1-RTT[STREAM] ---------------------->|
  |                                         |
  |<-- 1-RTT[HANDSHAKE_DONE] --------------|
  |<-- 1-RTT[STREAM] ----------------------|
```

- Client sends ClientHello in an Initial packet (padded to >= 1200 bytes).
- Server responds with ServerHello (Initial) + encrypted extensions, certificate, certificate verify, finished (Handshake).
- Client completes with Finished (Handshake), can immediately send 1-RTT data.
- Server sends HANDSHAKE_DONE frame to signal handshake completion.

### 0-RTT (Section 4.6.1)

- Client uses a previously received session ticket.
- Sends 0-RTT packets alongside the Initial.
- Server may accept or reject 0-RTT data.
- 0-RTT data is not forward-secret and is replayable; applications must account for this.

---


## 7. Streams (Sections 2-3)

### Stream Types

| Bit Pattern | Initiator | Direction |
|-------------|-----------|-----------|
| 0x00 | Client | Bidirectional |
| 0x01 | Server | Bidirectional |
| 0x02 | Client | Unidirectional |
| 0x03 | Server | Unidirectional |

The two least-significant bits of a stream ID encode the type.

### Stream State Machine

See [QUIC_STREAMS_SPEC.md §3](../specs/QUIC_STREAMS_SPEC.md#3-stream-states-rfc-9000-section-3) for the complete state machine. Briefly:

**Sending states**: Ready → Send → Data Sent → Data Recvd (terminal) / Reset Sent → Reset Recvd (terminal)

**Receiving states**: Recv → Size Known → Data Recvd (terminal) / Reset Recvd → Data Read (terminal) / Reset Read (terminal)

### Flow Control (Section 4)

- **Connection-level**: MAX_DATA frame; limits total bytes across all streams.
- **Stream-level**: MAX_STREAM_DATA frame; limits bytes on a single stream.
- **Stream count**: MAX_STREAMS frame; limits concurrent streams by type.
- Credit-based: receiver advertises limits; sender must not exceed them.

---


## 8. Connection Migration (Section 9)

- Only the client initiates migration.
- Path validation via PATH_CHALLENGE / PATH_RESPONSE.
- Anti-amplification: server limits data sent to an unvalidated address to 3x received.
- Connection IDs isolate activity across paths (linkability protection).
- Peer must validate new path before sending significant data.

---


## 9. Transport Parameters (Section 18)

Exchanged during handshake via TLS extensions. Key parameters:

| Parameter | Purpose |
|-----------|---------|
| `initial_max_data` | Connection-level flow control |
| `initial_max_stream_data_bidi_local` | Stream flow control (local-init bidi) |
| `initial_max_stream_data_bidi_remote` | Stream flow control (remote-init bidi) |
| `initial_max_stream_data_uni` | Stream flow control (uni) |
| `initial_max_streams_bidi` | Max concurrent bidi streams |
| `initial_max_streams_uni` | Max concurrent uni streams |
| `max_idle_timeout` | Connection idle timeout |
| `max_udp_payload_size` | Max UDP payload the endpoint will accept |
| `active_connection_id_limit` | Max CIDs stored |
| `disable_active_migration` | Peer should not migrate |

---


## 10. Security Considerations (Section 21)

- **Handshake denial-of-service**: Initial packet must be >= 1200 bytes (amplification limit); Retry token mechanism for address validation.
- **Amplification attacks**: Before address validation, server limited to 3x data received.
- **Connection ID linkability**: Peers use NEW_CONNECTION_ID to rotate; reduces tracking across paths.
- **Stateless reset**: Endpoint can send a stateless reset (using a token derived from CID) when it has lost state.
- **Version downgrade**: Version negotiation (RFC 8999) prevents downgrade attacks.

---


## 11. Relevance to dart_quic

1. **Variable-length integer encoding** must be a foundational codec in Dart.
2. **Packet parsing** must handle both long and short headers with zero-copy where possible.
3. **Stream multiplexing** maps naturally to Dart's `Stream<List<int>>` / `StreamSink<List<int>>`.
4. **Connection migration** requires abstracting connection identity from socket binding.
5. **Flow control** must be credit-based and apply at both connection and stream levels.
6. **Transport parameters** must be serializable into TLS extensions.
7. **PADDING to 1200 bytes** is required for Initial packets (anti-amplification).

---


## 12. References

- RFC 9000: https://www.rfc-editor.org/rfc/rfc9000
- RFC 8999 (QUIC Invariants): https://www.rfc-editor.org/rfc/rfc8999
- RFC 9001 (Using TLS): https://www.rfc-editor.org/rfc/rfc9001
- RFC 9002 (Loss Detection): https://www.rfc-editor.org/rfc/rfc9002
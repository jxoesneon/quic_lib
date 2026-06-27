# RFC 9000 Notes: QUIC: A UDP-Based Multiplexed and Secure Transport

**RFC**: 9000  
**Authors**: J. Iyengar (Ed.), M. Thomson (Ed.)  
**Published**: May 2021  
**Status**: Standards Track  
**Companion RFCs**: 9001 (TLS), 9002 (Recovery), 8999 (Invariants)

---

## Abstract

RFC 9000 defines the core QUIC transport protocol. QUIC provides applications with flow-controlled streams for structured communication, low-latency connection establishment, and network path migration. It includes security measures ensuring confidentiality, integrity, and availability.

---

## Key Design Principles

1. **UDP substrate**: QUIC packets are carried in UDP datagrams to facilitate deployment through existing NATs and middleboxes.
2. **Encryption by default**: The entirety of each packet is authenticated; nearly all content is encrypted. Only the invariant header fields (flags, version, connection IDs) are visible to on-path elements.
3. **Stream multiplexing without head-of-line blocking**: Unlike TCP+TLS+HTTP/2, loss in one stream does not block others.
4. **Connection migration**: Connections are identified by Connection IDs, not 4-tuples, enabling seamless migration across network changes.
5. **Low-latency handshake**: 1-RTT for new connections; 0-RTT for resumed connections.

---

## Packet Structure

### Header Types

| Header Type | Use Case | Key Properties |
|-------------|----------|----------------|
| **Long Header** | Handshake packets (Initial, Handshake, 0-RTT, Retry) | Contains Version, DCID Len, DCID, SCID Len, SCID |
| **Short Header** | Post-handshake (1-RTT) | Contains only DCID; minimal overhead |

### Variable-Length Integer Encoding (Section 16)

QUIC uses a variable-length integer encoding for most numeric values:

| 2-MSB | Length | Usable Bits | Maximum Value |
|-------|--------|-------------|---------------|
| 00    | 1 byte | 6           | 63            |
| 01    | 2 bytes| 14          | 16383         |
| 10    | 4 bytes| 30          | 1073741823    |
| 11    | 8 bytes| 62          | 4611686018427387903 |

### Packet Types (Long Header)

| Type Value | Packet Type | Encryption Level |
|-----------|-------------|------------------|
| 0x00      | Initial     | Initial secrets (derived from DCID) |
| 0x01      | 0-RTT       | Early data keys |
| 0x02      | Handshake   | Handshake keys |
| 0x03      | Retry       | None (integrity-tagged) |

---

## Frame Types (Section 12.4)

| Type | Name | Description |
|------|------|-------------|
| 0x00 | PADDING | No-op; used to increase packet size |
| 0x01 | PING | Keepalive / ack-eliciting |
| 0x02-0x03 | ACK | Acknowledge received packets |
| 0x04 | RESET_STREAM | Abruptly terminate sending on a stream |
| 0x05 | STOP_SENDING | Request peer stop sending on a stream |
| 0x06 | CRYPTO | Carry TLS handshake messages |
| 0x07 | NEW_TOKEN | Provide token for future connection attempts |
| 0x08-0x09 | STREAM | Carry application data |
| 0x10 | MAX_DATA | Connection-level flow control |
| 0x11 | MAX_STREAM_DATA | Stream-level flow control |
| 0x12-0x13 | MAX_STREAMS | Limit peer's stream creation |
| 0x14 | DATA_BLOCKED | Signal flow control limit reached |
| 0x15 | STREAM_DATA_BLOCKED | Signal stream flow control limit |
| 0x16-0x17 | STREAMS_BLOCKED | Signal stream creation limit |
| 0x18 | NEW_CONNECTION_ID | Provide new CID to peer |
| 0x19 | RETIRE_CONNECTION_ID | Retire a CID |
| 0x1a | PATH_CHALLENGE | Path validation probe |
| 0x1b | PATH_RESPONSE | Path validation response |
| 0x1c-0x1d | CONNECTION_CLOSE | Terminate connection |
| 0x1e | HANDSHAKE_DONE | Server signals handshake completion |

---

## Connection Lifecycle

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

## Streams (Sections 2-3)

### Stream Types

| Bit Pattern | Initiator | Direction |
|-------------|-----------|-----------|
| 0x00 | Client | Bidirectional |
| 0x01 | Server | Bidirectional |
| 0x02 | Client | Unidirectional |
| 0x03 | Server | Unidirectional |

The two least-significant bits of a stream ID encode the type.

### Stream State Machine

**Sending states**: Ready → Send → Data Sent → Data Recvd (terminal) / Reset Sent → Reset Recvd (terminal)

**Receiving states**: Recv → Size Known → Data Recvd (terminal) / Reset Recvd → Data Read (terminal) / Reset Read (terminal)

### Flow Control (Section 4)

- **Connection-level**: MAX_DATA frame; limits total bytes across all streams.
- **Stream-level**: MAX_STREAM_DATA frame; limits bytes on a single stream.
- **Stream count**: MAX_STREAMS frame; limits concurrent streams by type.
- Credit-based: receiver advertises limits; sender must not exceed them.

---

## Connection Migration (Section 9)

- Only the client initiates migration.
- Path validation via PATH_CHALLENGE / PATH_RESPONSE.
- Anti-amplification: server limits data sent to an unvalidated address to 3x received.
- Connection IDs isolate activity across paths (linkability protection).
- Peer must validate new path before sending significant data.

---

## Transport Parameters (Section 18)

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

## Security Considerations (Section 21)

- **Handshake denial-of-service**: Initial packet must be >= 1200 bytes (amplification limit); Retry token mechanism for address validation.
- **Amplification attacks**: Before address validation, server limited to 3x data received.
- **Connection ID linkability**: Peers use NEW_CONNECTION_ID to rotate; reduces tracking across paths.
- **Stateless reset**: Endpoint can send a stateless reset (using a token derived from CID) when it has lost state.
- **Version downgrade**: Version negotiation (RFC 8999) prevents downgrade attacks.

---

## Relevance to dart_quic

1. **Variable-length integer encoding** must be a foundational codec in Dart.
2. **Packet parsing** must handle both long and short headers with zero-copy where possible.
3. **Stream multiplexing** maps naturally to Dart's `Stream<List<int>>` / `StreamSink<List<int>>`.
4. **Connection migration** requires abstracting connection identity from socket binding.
5. **Flow control** must be credit-based and apply at both connection and stream levels.
6. **Transport parameters** must be serializable into TLS extensions.
7. **PADDING to 1200 bytes** is required for Initial packets (anti-amplification).

---

## References

- RFC 9000: https://www.rfc-editor.org/rfc/rfc9000
- RFC 8999 (QUIC Invariants): https://www.rfc-editor.org/rfc/rfc8999
- RFC 9001 (Using TLS): https://www.rfc-editor.org/rfc/rfc9001
- RFC 9002 (Loss Detection): https://www.rfc-editor.org/rfc/rfc9002

# RFC and Research Notes Consolidated

> This document consolidates all prior research notes into a single reference file.
> Original files are preserved in full, demarcated by source filename.


---

<!-- SOURCE: doc/research/RFC_9000_NOTES.md -->

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

RFC 9000 is a dense, 150-page specification that every implementer must internalize. These notes distill the core concepts-packet structure, stream types, connection lifecycle, migration, and transport parameters-into a quick-reference format that keeps the quic_lib team aligned without requiring constant re-reading of the full RFC.

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

QUIC uses a variable-length integer encoding for most numeric values. See [QUIC_WIRE_SPEC.md Â§2](../specs/QUIC_WIRE_SPEC.md#2-variable-length-integer-encoding-rfc-9000-section-16) for the canonical encoding table.

### Packet Types (Long Header)

See [QUIC_WIRE_SPEC.md Â§3](../specs/QUIC_WIRE_SPEC.md#3-packet-types-and-headers-rfc-9000-section-17) for the complete packet type reference. The four long-header types are Initial, 0-RTT, Handshake, and Retry.

---


## 5. Frame Types (Section 12.4)

RFC 9000 defines 19 frame types for connection management, flow control, stream data, and path validation. See [QUIC_WIRE_SPEC.md Â§4](../specs/QUIC_WIRE_SPEC.md#4-frame-types-and-formats-rfc-9000-section-19) for the complete frame type reference and wire encoding details. |

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

See [QUIC_STREAMS_SPEC.md Â§3](../specs/QUIC_STREAMS_SPEC.md#3-stream-states-rfc-9000-section-3) for the complete state machine. Briefly:

**Sending states**: Ready â†’ Send â†’ Data Sent â†’ Data Recvd (terminal) / Reset Sent â†’ Reset Recvd (terminal)

**Receiving states**: Recv â†’ Size Known â†’ Data Recvd (terminal) / Reset Recvd â†’ Data Read (terminal) / Reset Read (terminal)

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


## 11. Relevance to quic_lib

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

---

<!-- SOURCE: doc/research/RFC_9001_NOTES.md -->

---
title: "RFC 9001 Notes: Using TLS to Secure QUIC"
category: research
authors: "M. Thomson (Ed.), S. Turner (Ed.)"
published: "May 2021"
companion_rfcs: []
---

# RFC 9001 Notes: Using TLS to Secure QUIC


---

## 1. Purpose

QUIC replaces the TLS record layer entirely, carrying handshake messages in CRYPTO frames and deriving packet-protection keys via HKDF. This architectural shift is easy to misunderstand-especially around encryption levels, nonce construction, and header protection. These notes ensure the crypto and wire teams share the same mental model.

## 2. Abstract

RFC 9001 describes how TLS 1.3 is used to secure QUIC connections. QUIC takes over the responsibilities of the TLS record layer â€” TLS handshake and alert messages are carried directly in QUIC CRYPTO frames rather than in TLS records.

---


## 3. Architecture: QUIC + TLS Integration

```
+------------+                        +------------+
|    TLS     |--- handshake msgs ---->|    TLS     |
| (endpoint) |<--- handshake msgs ----|  (endpoint)|
+-----+------+                        +-----+------+
      |  ^                                   |  ^
      |  | (secrets)                         |  | (secrets)
      v  |                                   v  |
+-----+------+                        +-----+------+
|   QUIC     |====== QUIC packets ====|   QUIC     |
| (transport)|                        | (transport)|
+------------+                        +------------+
```

Key architectural decision: QUIC replaces the TLS record layer entirely. TLS only provides:
1. Handshake message generation/consumption
2. Key derivation
3. Alert signaling

QUIC provides:
1. Reliable, ordered delivery of handshake messages (via CRYPTO frames)
2. Packet protection (encryption + authentication)
3. Key update mechanism

---


## 4. Encryption Levels (Section 4)

QUIC uses four encryption levels, each corresponding to a TLS epoch:

| Level | TLS Epoch | Used For | Key Source |
|-------|-----------|----------|------------|
| Initial | â€” | First flight, before any TLS output | Derived from client DCID |
| 0-RTT (Early Data) | early_data | Resumed session early data | `client_early_traffic_secret` |
| Handshake | handshake | Handshake completion | `client/server_handshake_traffic_secret` |
| 1-RTT (Application) | application_data | Post-handshake data | `client/server_application_traffic_secret_0` |

---


## 5. Initial Secrets Derivation (Section 5.2)

Initial secrets are **not** derived from a TLS handshake. They use a well-known salt and the client's initial Destination Connection ID. See [QUIC_CRYPTO_SPEC.md Â§3](../specs/QUIC_CRYPTO_SPEC.md#3-initial-secrets-and-packet-protection-rfc-9001-section-5) for the complete derivation and exact test vectors.

These provide confidentiality only against passive observers â€” an active attacker who sees the Initial packet can derive the same keys.

---


## 6. Key Derivation (Section 5.1)

From each traffic secret, QUIC derives:

```
key  = HKDF-Expand-Label(secret, "quic key", "", key_length)
iv   = HKDF-Expand-Label(secret, "quic iv",  "", 12)
hp   = HKDF-Expand-Label(secret, "quic hp",  "", hp_key_length)
```

- `key`: AEAD encryption key
- `iv`: Initialization vector (nonce base)
- `hp`: Header protection key

All `HKDF-Expand-Label` calls use a zero-length Context (empty string).

---


## 7. Packet Protection (Section 5.3-5.4)

### AEAD Encryption

- Nonce = `iv XOR packet_number` (packet number left-padded with zeros to 12 bytes)
- Associated Data (AD) = the QUIC packet header (up to and including the unprotected packet number)
- Plaintext = packet payload (frames)
- Ciphertext = AEAD output (payload + 16-byte authentication tag for AES-128-GCM/AES-256-GCM or Poly1305 tag for ChaCha20)

### Header Protection

Applied **after** payload encryption to obscure the packet number length and value:

1. Sample 16 bytes from the ciphertext (starting at byte 4 of the packet number field offset).
2. Use the `hp` key to generate a 5-byte mask:
   - AES-based: `mask = AES-ECB(hp_key, sample)`
   - ChaCha20-based: `mask = ChaCha20(hp_key, sample[0..3] as counter, sample[4..15] as nonce)`
3. XOR the first byte of the header with `mask[0]` (protecting flags).
4. XOR the packet number bytes with `mask[1..4]`.

---


## 8. Supported Cipher Suites (Section 5.3)

| TLS Cipher Suite | AEAD | Key Length | IV Length | HP Algorithm |
|------------------|------|------------|-----------|--------------|
| TLS_AES_128_GCM_SHA256 | AES-128-GCM | 16 | 12 | AES-ECB |
| TLS_AES_256_GCM_SHA384 | AES-256-GCM | 32 | 12 | AES-ECB |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20-Poly1305 | 32 | 12 | ChaCha20 |

---


## 9. Key Update (Section 6)

After the handshake completes, either endpoint can initiate a key update:

```
application_traffic_secret_N+1 =
    HKDF-Expand-Label(application_traffic_secret_N, "quic ku", "", Hash.length)
```

- Signaled by toggling the Key Phase bit in the short header.
- Both endpoints maintain current and next-generation keys for a transition period.
- Only one update can be in progress at a time.
- Initiator must wait for acknowledgment of a packet with the new key phase before initiating another update.

---


## 10. Retry Integrity (Section 5.8)

Retry packets use a fixed key and nonce (published in the RFC) to compute an integrity tag:

```
retry_key  = 0xbe0c690b9f66575a1d766b54e368c84e  (QUIC v1)
retry_nonce = 0x461599d35d632bf2239825bb
```

This prevents off-path modification of Retry packets while remaining stateless for the server.

---


## 11. TLS Handshake Messages in QUIC (Section 4)

TLS handshake messages are carried in CRYPTO frames at the appropriate encryption level:

| Message | Encryption Level |
|---------|-----------------|
| ClientHello | Initial |
| ServerHello | Initial |
| EncryptedExtensions | Handshake |
| CertificateRequest | Handshake |
| Certificate | Handshake |
| CertificateVerify | Handshake |
| Finished (server) | Handshake |
| Finished (client) | Handshake |
| NewSessionTicket | 1-RTT |

---


## 12. QUIC Transport Parameters TLS Extension (Section 8.2)

QUIC transport parameters are sent as a TLS extension (`quic_transport_parameters`, code point 0x0039`). Both endpoints include this extension in their handshake:

- Client: in ClientHello
- Server: in EncryptedExtensions

Parameters are encoded as a sequence of (ID, length, value) tuples.

---


## 13. Security Considerations for quic_lib

1. **Initial secrets are public**: Any observer who sees the DCID can derive Initial keys. Initial packets provide integrity but not true confidentiality.
2. **Constant-time operations**: Key derivation and packet protection must use constant-time comparisons to prevent timing attacks.
3. **Key phase bit**: Must correctly track key generations; mishandling causes connection failure.
4. **0-RTT replay**: Application must be aware that 0-RTT data can be replayed; Dart API should clearly mark 0-RTT data.
5. **Certificate validation**: Standard X.509 certificate chain validation must be performed (or custom validation for libp2p).

---


## 14. Implementation Notes for Dart

- `package:cryptography` or `package:pointycastle` can provide AES-GCM, ChaCha20-Poly1305, and HKDF.
- Header protection requires either AES-ECB (single-block) or ChaCha20 (5-byte mask generation).
- The nonce construction (XOR with packet number) is simple but must correctly left-pad.
- CRYPTO frames must be reassembled in order within each encryption level (QUIC guarantees this per-level).

---


## 15. References

- RFC 9001: https://www.rfc-editor.org/rfc/rfc9001
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869

---

<!-- SOURCE: doc/research/RFC_9002_NOTES.md -->

---
title: "RFC 9002 Notes: QUIC Loss Detection and Congestion Control"
category: research
authors: "J. Iyengar (Ed.), I. Swett (Ed.)"
published: "May 2021"
companion_rfcs: []
---

# RFC 9002 Notes: QUIC Loss Detection and Congestion Control


---

## 1. Purpose

Loss detection and congestion control in QUIC differ from TCP in subtle but critical ways: separate packet number spaces, unambiguous RTT samples, and integrated probe timeouts. Misunderstanding any of these leads to stalled connections or network abuse. These notes provide the algorithmic details that the recovery implementation must match.

## 2. Abstract

RFC 9002 describes loss detection and congestion control mechanisms for QUIC. It specifies a loss detection algorithm based on packet number acknowledgment and a congestion controller similar to TCP NewReno.

---


## 3. Design Context

Unlike TCP, QUIC:
- Uses **per-packet** sequence numbers (never retransmits the same packet number).
- Has **separate packet number spaces** for Initial, Handshake, and Application Data.
- Carries ACKs that are **not** congestion-controlled.
- Knows which specific packets were acknowledged (no ambiguity from retransmission).

This eliminates TCP's retransmission ambiguity and enables cleaner loss detection.

---


## 4. RTT Measurement (Section 5)

### Variables

| Variable | Description |
|----------|-------------|
| `latest_rtt` | RTT of the most recently ack'd packet |
| `smoothed_rtt` | Exponentially weighted moving average |
| `rttvar` | RTT variation (mean deviation) |
| `min_rtt` | Minimum RTT observed (not smoothed) |

### Update Algorithm

```
On first RTT sample:
  smoothed_rtt = latest_rtt
  rttvar = latest_rtt / 2
  min_rtt = latest_rtt

On subsequent samples:
  ack_delay = min(ack_delay_field, max_ack_delay)  // clamped
  adjusted_rtt = latest_rtt
  if (latest_rtt >= min_rtt + ack_delay):
    adjusted_rtt = latest_rtt - ack_delay
  
  rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
  smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
```

---


## 5. Loss Detection (Section 6)

### Packet Threshold

A packet is declared lost if a **newer** packet in the same packet number space has been acknowledged and the gap exceeds `kPacketThreshold` (default: 3).

```
if (largest_acked - packet.number >= kPacketThreshold):
  declare_lost(packet)
```

### Time Threshold

A packet is declared lost if sufficient time has elapsed since it was sent:

```
loss_delay = max(9/8 * max(latest_rtt, smoothed_rtt), kGranularity)
// kGranularity = 1ms (timer granularity)

if (time_since_sent > loss_delay):
  declare_lost(packet)
```

### Probe Timeout (PTO) (Section 6.2)

When no ACK is received within the PTO, the sender sends a probe to elicit an acknowledgment:

```
PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
```

- PTO probe sends new data if available, otherwise retransmits.
- PTO is armed per packet number space during handshake.
- Consecutive PTOs double the timeout (exponential backoff).
- PTO count resets when an ACK is received.

---


## 6. Congestion Control (Section 7)

### Algorithm: NewReno-like

QUIC specifies a congestion controller similar to TCP NewReno with the following states:

| State | Condition | Behavior |
|-------|-----------|----------|
| **Slow Start** | `cwnd < ssthresh` | `cwnd += bytes_acked` per ACK |
| **Congestion Avoidance** | `cwnd >= ssthresh` | `cwnd += max_datagram_size * bytes_acked / cwnd` per ACK |
| **Recovery** | After loss detection | `ssthresh = cwnd / 2; cwnd = ssthresh` |

### Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `kInitialWindow` | `min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))` | Initial cwnd |
| `kMinimumWindow` | `2 * max_datagram_size` | Minimum cwnd after loss |
| `kPacketThreshold` | 3 | Packet reordering tolerance |
| `kTimeThreshold` | 9/8 | Time reordering factor |
| `kGranularity` | 1ms | Timer granularity |

### ECN (Explicit Congestion Notification) (Section 13.4 of RFC 9000)

- QUIC supports ECN marking (ECT(0), ECT(1), CE).
- ACK frames carry ECN counts.
- An increase in CE count triggers congestion response (same as loss).
- ECN validation: endpoints verify that ECN counts are consistent with sent packets.

---


## 7. Persistent Congestion (Section 7.6.2)

If packets are lost over a duration exceeding the persistent congestion period, the sender assumes the path has fundamentally changed:

```
persistent_congestion_duration = 3 * (smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay)

if (duration_between_lost_packets > persistent_congestion_duration):
  cwnd = kMinimumWindow
```

This is analogous to a TCP timeout retransmission.

---


## 8. Pacing (Section 7.7)

Recommended but not required. Sends packets at a rate matching the congestion window:

```
interval = smoothed_rtt * max_datagram_size / cwnd
```

Pacing reduces burstiness and improves fairness with other flows.

---


## 9. Under-Utilized Connections (Section 7.8)

- If the application is not sending enough to fill the cwnd, the sender SHOULD NOT increase cwnd.
- `bytes_in_flight` must be at or near `cwnd` for congestion events to reduce the window.

---


## 10. Per-Space vs. Per-Path

| Property | Scope |
|----------|-------|
| Loss detection | Per packet number space |
| RTT measurement | Per path (shared across spaces) |
| Congestion control | Per path (shared across spaces) |

---


## 11. Differences from TCP Recovery

| TCP | QUIC |
|-----|------|
| Retransmits same sequence numbers | Always uses new packet numbers |
| Ambiguous RTT on retransmission | Unambiguous RTT (unique packet numbers) |
| SACK optional | ACK ranges always available |
| Single sequence space | Separate spaces per encryption level |
| Timeout uses RTO | Uses PTO (more aggressive probing) |
| Tail loss probe is separate RFC | PTO integrated into base spec |

---


## 12. Relevance to quic_lib

1. **Timer precision**: Dart's timer system (`Timer`, `Stopwatch`) must provide at least millisecond granularity for PTO and loss detection.
2. **Per-space tracking**: The implementation needs separate sent-packet lists per encryption level.
3. **Congestion state**: A `CongestionController` class should encapsulate cwnd, ssthresh, bytes_in_flight, and the state machine.
4. **Pluggable algorithms**: The spec encourages experimentation (e.g., CUBIC). The Dart API should allow swapping congestion algorithms.
5. **Pacing**: Consider a token-bucket or leaky-bucket pacer for production quality.
6. **ACK processing**: Must handle ACK ranges efficiently (RFC 9000 Section 19.3) to detect lost packets.

---


## 13. References

- RFC 9002: https://www.rfc-editor.org/rfc/rfc9002
- RFC 9000 Section 13 (Packet Processing): https://www.rfc-editor.org/rfc/rfc9000#section-13
- RFC 6582 (NewReno): https://www.rfc-editor.org/rfc/rfc6582
- RFC 8312 (CUBIC): https://www.rfc-editor.org/rfc/rfc8312
- RFC 6928 (Initial Window): https://www.rfc-editor.org/rfc/rfc6928

---

<!-- SOURCE: doc/research/RFC_9114_NOTES.md -->

---
title: "RFC 9114 Notes: HTTP/3"
category: research
published: "June 2022"
companion_rfcs: []
---

# RFC 9114 Notes: HTTP/3


---

## 1. Purpose

HTTP/3 over QUIC is not simply HTTP/2 over UDP; it replaces HPACK with QPACK, redefines stream roles, and eliminates TCP head-of-line blocking. These notes capture the mapping between QUIC streams and HTTP semantics so that the HTTP/3 layer is built on a correct understanding of RFC 9114.

## 2. Abstract

RFC 9114 defines HTTP/3, the mapping of HTTP semantics over the QUIC transport protocol. It replaces TCP+TLS+HTTP/2 with QUIC, eliminating head-of-line blocking at the transport layer while preserving HTTP's request-response semantics.

---


## 3. Key Differences from HTTP/2

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


## 4. Stream Mapping (Section 6)

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


## 5. Frame Types (Section 7)

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


## 6. Request/Response Exchange (Section 4)

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


## 7. SETTINGS Frame (Section 7.2.4)

Sent on the control stream immediately after stream creation:

| Setting | ID | Default | Description |
|---------|----|---------|-------------|
| SETTINGS_MAX_FIELD_SECTION_SIZE | 0x06 | Unlimited | Max size of decoded header section |
| SETTINGS_QPACK_MAX_TABLE_CAPACITY | 0x01 | 0 | Max dynamic table size for QPACK |
| SETTINGS_QPACK_BLOCKED_STREAMS | 0x07 | 0 | Max streams that can be blocked on QPACK |

HTTP/2 settings (like SETTINGS_ENABLE_PUSH) are **not** valid in HTTP/3 and MUST NOT be sent.

---


## 8. Connection Shutdown (Section 5.2)

- **GOAWAY frame**: Contains a Stream ID or Push ID indicating the last one the sender will process.
- Receiver should not initiate new requests on streams with IDs >= the indicated value.
- Allows graceful connection draining.

---


## 9. Error Handling (Section 8)

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


## 10. Server Push (Section 4.6)

1. Server sends PUSH_PROMISE on a request stream (contains push ID + request headers).
2. Server sends MAX_PUSH_ID on control stream to expand push ID space.
3. Server opens a unidirectional push stream (stream type 0x01) with push ID.
4. Server sends HEADERS + DATA on the push stream.
5. Client can CANCEL_PUSH to reject.

---


## 11. Security Considerations (Section 10)

- All HTTP/3 communication is encrypted (inherits from QUIC).
- Server push must be carefully validated; clients should not blindly cache pushed responses.
- Header compression (QPACK) has been designed to avoid CRIME/BREACH-style attacks.
- Connection coalescing: clients may reuse connections to different origins if the certificate covers them.

---


## 12. Relevance to quic_lib

1. **Stream type detection**: First bytes of unidirectional streams indicate their type â€” need a dispatcher.
2. **QPACK integration**: Separate encoder/decoder streams must be managed alongside request streams.
3. **Frame parsing**: HTTP/3 frames use QUIC's variable-length integer encoding for type and length.
4. **Request/response mapping**: Each bidirectional stream maps to one `HttpRequest`/`HttpResponse` pair in Dart.
5. **Settings negotiation**: Must exchange SETTINGS before any request/response on the control stream.
6. **Graceful shutdown**: GOAWAY support needed for connection draining.
7. **Error propagation**: HTTP/3 errors map to QUIC stream/connection errors; need a unified error hierarchy.

---


## 13. References

- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114
- RFC 9204 (QPACK): https://www.rfc-editor.org/rfc/rfc9204
- RFC 9000 (QUIC): https://www.rfc-editor.org/rfc/rfc9000
- RFC 9110 (HTTP Semantics): https://www.rfc-editor.org/rfc/rfc9110

---

<!-- SOURCE: doc/research/RFC_9204_NOTES.md -->

---
title: "RFC 9204 Notes: QPACK: Field Compression for HTTP/3"
category: research
authors: "C. Krasic, M. Bishop, A. Frindell (Eds.)"
published: "June 2022"
companion_rfcs: []
---

# RFC 9204 Notes: QPACK: Field Compression for HTTP/3


---

## 1. Purpose

QPACK explicit encoder/decoder streams and blocking-tolerant references are a significant departure from HPACK implicit dynamic table updates. Implementing QPACK without understanding these design choices risks either head-of-line blocking or poor compression ratios. These notes provide the conceptual foundation for the QPACK codec spec.

## 2. Abstract

QPACK is a compression format for efficiently representing HTTP header and trailer fields in HTTP/3. It is a variation of HPACK (RFC 7541) redesigned for QUIC's out-of-order delivery, trading off compression ratio for reduced head-of-line blocking.

---


## 3. Why Not HPACK?

HPACK requires in-order delivery of compressed field sections because the dynamic table is updated implicitly by each encoded section. In HTTP/2 over TCP, this ordering is guaranteed. In HTTP/3 over QUIC, streams are delivered independently â€” HPACK would cause head-of-line blocking at the application layer.

QPACK solves this by:
1. Using **explicit instructions** on a dedicated encoder stream to update the dynamic table.
2. Allowing **unacknowledged references** with configurable blocking tolerance.
3. Using a **decoder stream** for acknowledgments.

---


## 4. Architecture

```
Encoder                                  Decoder
   |                                        |
   |--- Encoder Stream (unidirectional) --->|  (table update instructions)
   |                                        |
   |<-- Decoder Stream (unidirectional) ----|  (acknowledgments)
   |                                        |
   |--- Request Stream (HEADERS frame) ---->|  (encoded field section)
   |                                        |
```

---


## 5. Tables

See [HTTP3_SPEC.md Â§2.4](../specs/HTTP3_SPEC.md#24-qpack-integration-rfc-9204) for the QPACK integration context; the complete codec is specified in [QPACK_SPEC.md](../specs/QPACK_SPEC.md). including static table, dynamic table, and encoder/decoder instructions. Briefly:

- **Static Table**: 99 predefined entries with common HTTP fields.
- **Dynamic Table**: FIFO queue of (name, value) entries, capacity set via `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
- Both endpoints maintain synchronized copies updated via encoder instructions.

---


## 6. Encoder Instructions (Section 4.3)

Sent on the encoder stream:

| Instruction | Prefix | Description |
|-------------|--------|-------------|
| Set Dynamic Table Capacity | `001` (3-bit) | Change table capacity |
| Insert With Name Reference | `1` (1-bit) | Insert entry referencing existing name |
| Insert With Literal Name | `01` (2-bit) | Insert entry with literal name |
| Duplicate | `000` (3-bit) | Duplicate existing entry |

---


## 7. Decoder Instructions (Section 4.4)

Sent on the decoder stream:

| Instruction | Prefix | Description |
|-------------|--------|-------------|
| Section Acknowledgment | `1` (1-bit) | Acknowledge processing of a field section |
| Stream Cancellation | `01` (2-bit) | Notify encoder that a stream was cancelled |
| Insert Count Increment | `00` (2-bit) | Inform encoder of new entries received |

---


## 8. Encoded Field Section (Section 4.5)

Each HEADERS frame carries a field section with:

```
Encoded Field Section {
  Required Insert Count (8+),    // prefix-encoded integer
  Sign bit (1),
  Delta Base (7+),               // prefix-encoded integer
  Encoded Field Lines (..)       // sequence of representations
}
```

### Field Line Representations

| Representation | Prefix | Description |
|----------------|--------|-------------|
| Indexed (static) | `1, T=1` | Reference to static table |
| Indexed (dynamic) | `1, T=0` | Reference to dynamic table |
| Indexed (post-base) | `0001` | Reference to dynamic entry after base |
| Literal with name ref | `01` | Literal value, name from table |
| Literal with literal name | `001` | Both name and value literal |
| Literal with post-base name ref | `0000` | Literal value, name from post-base entry |

---


## 9. Blocking and Required Insert Count

- **Required Insert Count**: The minimum number of dynamic table inserts the decoder must have processed to decode the field section.
- If the decoder hasn't received enough encoder instructions, it blocks.
- `SETTINGS_QPACK_BLOCKED_STREAMS`: Maximum number of streams that may be simultaneously blocked.
- Encoder can avoid blocking entirely by only referencing the static table or already-acknowledged dynamic entries.

---


## 10. Integer Encoding (Section 4.1)

QPACK uses the same prefix integer encoding as HPACK:

```
if value < 2^N - 1:
  encode value in N bits
else:
  encode 2^N - 1 in N bits
  value -= 2^N - 1
  while value >= 128:
    encode (value % 128) + 128 as one byte
    value /= 128
  encode value as one byte
```

---


## 11. String Encoding (Section 4.2)

Two modes:
1. **Huffman-encoded**: H-bit = 1; uses the HPACK Huffman table (Appendix B of RFC 7541).
2. **Raw**: H-bit = 0; literal bytes.

---


## 12. Security Considerations (Section 7)

- **Probing attacks** (CRIME/BREACH): Mitigated by QPACK's ability to use literal representations and by QUIC's encryption of per-stream data.
- **Memory exhaustion**: Dynamic table capacity is bounded by settings; implementations must enforce limits.
- **Denial of service**: Encoder must not send references beyond what the decoder has acknowledged.

---


## 13. Relevance to quic_lib

1. **Separate codec**: QPACK encoder/decoder should be a standalone module, testable independently.
2. **Static table**: Hardcode the 99-entry static table as a const list.
3. **Dynamic table**: Implement as a bounded FIFO with eviction.
4. **Huffman codec**: Reuse HPACK Huffman table; implement decode via a state machine for streaming.
5. **Blocking strategy**: Make blocking configurable via SETTINGS; default to conservative (no blocking) for simplicity.
6. **Stream coordination**: Encoder/decoder streams must be opened before any HEADERS frame can reference dynamic entries.

---


## 14. References

- RFC 9204: https://www.rfc-editor.org/rfc/rfc9204
- RFC 7541 (HPACK): https://www.rfc-editor.org/rfc/rfc7541
- RFC 9114 (HTTP/3): https://www.rfc-editor.org/rfc/rfc9114

---

<!-- SOURCE: doc/research/WEBTRANSPORT_DRAFT_NOTES.md -->

---
title: "WebTransport over HTTP/3 Draft Notes"
category: research
companion_rfcs: []
---

# WebTransport over HTTP/3 Draft Notes


---

## 1. Purpose

WebTransport over HTTP/3 is still evolving as an IETF draft, yet it is already shipping in Chromium and demanded by real-time Dart applications. These notes track the draft semantics-session establishment via extended CONNECT, capsule types, flow control, and session termination-that the WebTransport spec must codify.

## 2. Abstract

WebTransport over HTTP/3 is a protocol that enables web application clients (constrained by the web security model) to communicate with a remote server using a secure multiplexed transport. It provides unidirectional streams, bidirectional streams, and datagrams, all multiplexed within a single HTTP/3 connection.

---


## 3. Motivation

WebSocket provides a single bidirectional byte stream. For real-time applications (gaming, live media, collaborative editing), developers need:
- **Multiple independent streams** (no head-of-line blocking between messages)
- **Unreliable delivery** (datagrams for latency-sensitive data)
- **Server-initiated streams**
- **Multiplexing** with other HTTP traffic on the same connection

WebTransport over HTTP/3 provides all of these.

---


## 4. Session Establishment (Section 3)

### Prerequisites

1. Both endpoints must support HTTP/3 datagrams: `SETTINGS_H3_DATAGRAM = 1`
2. Both endpoints must support QUIC datagrams: `max_datagram_frame_size > 0` transport parameter
3. Server advertises WebTransport support: `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`

### CONNECT Request

A WebTransport session is established via an extended CONNECT request:

```
:method = CONNECT
:protocol = webtransport
:scheme = https
:authority = server.example.com
:path = /game-session
```

- Uses the extended CONNECT mechanism (RFC 8441 adapted for HTTP/3).
- The server responds with a 2xx status to accept.
- The CONNECT stream becomes the **session stream** â€” its lifetime bounds the session.

---


## 5. Features (Section 4)

### 4.1 Datagrams

- Sent using HTTP Datagrams (RFC 9297) associated with the session's CONNECT stream.
- Unreliable, unordered delivery.
- Size limited by `max_datagram_frame_size` transport parameter.
- Format: Quarter Stream ID (of CONNECT stream) + payload.

### 4.2 Unidirectional Streams

Either endpoint can open unidirectional QUIC streams associated with the session:

```
WebTransport Unidirectional Stream {
  Signal Value (i) = 0x54,     // identifies as WT uni stream
  Session ID (i),              // CONNECT stream ID
  Application Payload (..)
}
```

### 4.3 Bidirectional Streams

**Client-initiated**: Uses a signal value as the first bytes of a client-initiated bidirectional stream:

```
WebTransport Bidirectional Stream (client) {
  Signal Value (i) = 0x41,     // "WT bidi" signal
  Session ID (i),              // CONNECT stream ID  
  Application Payload (..)
}
```

**Server-initiated**: HTTP/3 normally doesn't allow server-initiated bidi streams. WebTransport extends this:

```
WebTransport Bidirectional Stream (server) {
  Signal Value (i) = 0x41,
  Session ID (i),
  Application Payload (..)
}
```

---


## 6. Session Lifecycle

```
Client                                        Server
  |                                             |
  |-- CONNECT :protocol=webtransport ---------->|
  |                                             |
  |<-- 200 OK ---------------------------------|
  |                                             |
  |== SESSION ESTABLISHED ======================|
  |                                             |
  |-- Datagram (unreliable) ------------------->|
  |<-- Datagram (unreliable) -------------------|
  |                                             |
  |-- Open unidirectional stream -------------->|
  |<-- Open unidirectional stream --------------|
  |                                             |
  |-- Open bidirectional stream --------------->|
  |<-- Open bidirectional stream ---------------|
  |                                             |
  |-- CLOSE (reset CONNECT stream) ------------>|
  |                                             |
```

### Session Termination

- Closing or resetting the CONNECT stream terminates the session.
- All associated streams and datagrams are implicitly terminated.
- Server can send `CLOSE_WEBTRANSPORT_SESSION` capsule with an error code and reason.

---


## 7. Multiplexing Multiple Sessions

Multiple WebTransport sessions can share a single HTTP/3 connection:
- Each has its own CONNECT stream (distinct stream ID).
- Streams/datagrams are associated with their session by Session ID.
- Sessions are independent; closing one does not affect others.

---


## 8. Capsule Protocol Integration

WebTransport uses the Capsule Protocol (RFC 9297) on the CONNECT stream for:

| Capsule | Purpose |
|---------|---------|
| `CLOSE_WEBTRANSPORT_SESSION` | Graceful session close with error code + reason |
| `DRAIN_WEBTRANSPORT_SESSION` | Signal intent to close; peer should stop new streams |

---


## 9. Flow Control Considerations

- WebTransport streams are QUIC streams and subject to QUIC flow control.
- Datagrams are not flow-controlled (they are unreliable).
- The HTTP/3 connection's flow control applies to the CONNECT stream carrying capsules.
- Each session's streams consume from the shared QUIC connection flow control budget.

---


## 10. Security Model

- Origin-based: The CONNECT request carries `:authority` and `:path` that identify the server application.
- Certificate validation: Standard HTTPS certificate validation applies.
- CORS-like: The web security model restricts which origins can establish sessions.
- No cross-origin data leakage through multiplexed sessions.

---


## 11. Relevance to quic_lib

1. **Layering**: WebTransport sits on top of HTTP/3, which sits on top of QUIC. The Dart implementation should maintain this layering cleanly.
2. **Session abstraction**: A `WebTransportSession` class should encapsulate:
   - The underlying CONNECT stream
   - Methods to open/accept unidirectional and bidirectional streams
   - Methods to send/receive datagrams
3. **Signal values**: Stream type detection must check for 0x41 (bidi) and 0x54 (uni) prefixes.
4. **Datagram API**: Expose a simple `sendDatagram(Uint8List)` / `Stream<Uint8List> get datagrams` interface.
5. **Multiple sessions**: Support multiplexing multiple sessions on one connection.
6. **Graceful close**: Support CLOSE_WEBTRANSPORT_SESSION and DRAIN capsules.

---


## 12. References

- draft-ietf-webtrans-http3: https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/
- RFC 9297 (HTTP Datagrams): https://www.rfc-editor.org/rfc/rfc9297
- RFC 9114 (HTTP/3): https://www.rfc-editor.org/rfc/rfc9114
- RFC 9221 (QUIC Datagrams): https://www.rfc-editor.org/rfc/rfc9221
- WebTransport Overview: https://datatracker.ietf.org/doc/draft-ietf-webtrans-overview/

---

<!-- SOURCE: doc/research/DART_ECOSYSTEM_GAP.md -->

---
title: "Dart Ecosystem Gap Analysis: Why Pure Dart Needs a QUIC Stack"
category: research
companion_rfcs: []
---

# Dart Ecosystem Gap Analysis: Why Pure Dart Needs a QUIC Stack


## 1. Purpose

The Dart ecosystem lacks a production-ready pure-Dart QUIC stack, which limits HTTP/3 adoption, WebTransport support, and libp2p participation in Dart projects that prefer pure-Dart dependencies. Understanding exactly what is missingâ€”and which existing packages fall shortâ€”helps justify the investment in quic_lib and shapes the architecture decisions that follow.

## 2. The Problem

As of mid-2026, the Dart ecosystem has **no production-ready, pure-Dart QUIC implementation**. This gap blocks:

1. **dart_ipfs**: Requires QUIC transport for libp2p (`/udp/.../quic-v1` multiaddr support).
2. **HTTP/3 adoption**: Dart servers and clients cannot natively speak HTTP/3.
3. **WebTransport**: Real-time web applications in Dart cannot use the WebTransport API.
4. **Edge/IoT**: Pure-Dart is essential for platforms where native FFI is unavailable or impractical (e.g., Dart Native on embedded, WASM compilation targets).

---


## 3. Current Landscape

### Official Dart SDK Position

- **dart:io**: Provides `RawDatagramSocket` for UDP, `SecureSocket` for TLS over TCP. No QUIC primitives.
- **GitHub Issue #38595** (dart-lang/sdk): "Add HTTP/3 support" â€” open since 2019. The Dart team's position: HTTP/3 should be a community-contributed package, not core SDK.
- **package:http**: TCP-only; no QUIC path.
- **Cronet integration** (package:cronet_http): Wraps Google's Chromium network stack via FFI. Supports QUIC/HTTP/3 but is **not pure Dart** and is mobile-only.

### Existing Dart Packages

| Package | Approach | QUIC | HTTP/3 | Pure Dart | Production |
|---------|----------|------|--------|-----------|------------|
| `cronet_http` | FFI to Chromium Cronet | Yes | Yes | No (native) | Mobile only |
| `pure_dart_quic` | Pure Dart | Partial | Basic | Yes | No (PoC) |
| `quic_lib` (this project) | Pure Dart | Planned | Planned | Yes | Spec stage |

### Gap Summary

| Requirement | Available? | Notes |
|-------------|-----------|-------|
| QUIC transport (RFC 9000) | No (pure Dart) | `pure_dart_quic` is PoC only |
| TLS 1.3 over QUIC (RFC 9001) | No | No pure-Dart QUIC-TLS integration |
| HTTP/3 (RFC 9114) | No (pure Dart) | Only via Cronet FFI |
| WebTransport | No | No implementation at all |
| libp2p QUIC | No | No `/quic-v1` transport in Dart libp2p |
| Congestion control | No | No pure-Dart implementation |
| Connection migration | No | Not implemented anywhere in Dart |

---


## 4. Constraints Unique to Dart

### 1. Single-Threaded Event Loop

Dart's concurrency model is a single-threaded event loop with isolates for parallelism. This means:
- **No shared mutable state between isolates** (message-passing only).
- **Non-blocking I/O is natural** (`async`/`await`, `Stream`).
- **CPU-intensive crypto must be offloaded** to isolates or native extensions.
- **Timer granularity** is limited by the event loop (microtask queue).

**Implication**: The QUIC implementation must be async-native. Crypto operations (AES-GCM, ChaCha20) that process many packets per second may need isolate offloading.

### 2. No Raw Socket Access (Beyond UDP)

- `RawDatagramSocket` provides UDP send/recv.
- No kernel bypass (no io_uring, no DPDK).
- No `sendmmsg`/`recvmmsg` (batch send/recv) â€” each datagram is a separate operation.
- GSO (Generic Segmentation Offload) unavailable.

**Implication**: Throughput ceiling is lower than C/Rust implementations. Acceptable for client-side and P2P use; may limit high-throughput server scenarios.

### 3. Crypto Availability

| Operation | Pure Dart | Native-Backed (package:cryptography) |
|-----------|-----------|--------------------------------------|
| AES-128-GCM | package:pointycastle (slow) | Yes (hardware-accelerated) |
| AES-256-GCM | package:pointycastle (slow) | Yes |
| ChaCha20-Poly1305 | package:pointycastle | Yes |
| HKDF-SHA256 | Yes | Yes |
| X25519 (key exchange) | Yes | Yes |
| Ed25519 (signing) | Yes | Yes |
| SHA-256 | Yes | Yes |

**Implication**: `package:cryptography` should be the primary crypto backend (uses platform-native implementations where available). Fallback to `package:pointycastle` for WASM or restricted environments.

### 4. No dart:ffi on All Targets

- dart:ffi works on native platforms (Linux, macOS, Windows, Android, iOS).
- NOT available on web (dart2js, dart2wasm).
- NOT reliably available on all embedded targets.

**Implication**: The core QUIC implementation must be pure Dart. Native crypto acceleration is an optimization, not a requirement.

### 5. WASM Compilation Target

Dart is increasingly targeting WASM (via `dart2wasm`). Constraints:
- No file system access.
- No raw UDP sockets (must use browser APIs or WASM networking proposals).
- Crypto via WebCrypto API.

**Implication**: WASM support is a future goal. The architecture should not preclude it, but the initial implementation targets `dart:io` (native) platforms.

---


## 5. Why Build This Now

### 1. dart_ipfs P0 Dependency

The `dart_ipfs` project requires QUIC transport as its P0 priority. Without it, the Dart libp2p implementation cannot participate in the standard IPFS network using QUIC multiaddrs.

### 2. HTTP/3 is Becoming the Default

Major CDNs and services are defaulting to HTTP/3. Dart servers that cannot speak HTTP/3 face:
- Higher latency (TCP handshake overhead).
- No 0-RTT.
- Head-of-line blocking.
- Inability to serve modern web clients optimally.

### 3. WebTransport for Real-Time Apps

Gaming, live collaboration, and streaming applications in Dart (Flutter) need WebTransport's unreliable datagrams and independent streams. The only alternative today is WebSocket, which has head-of-line blocking.

### 4. Ecosystem Gap = Opportunity

The Dart ecosystem is mature in many areas (HTTP clients, gRPC, protobuf) but has a noticeable gap in modern transport protocols. Filling this gap would provide a building block for Dart networking libraries such as `dart_ipfs`.

---


## 6. Design Principles Derived from Constraints

1. **Pure Dart core**: No FFI dependencies in the transport layer.
2. **Async-native**: Build on `Stream`/`Future`/`Completer` â€” no blocking anywhere.
3. **Crypto abstraction**: Interface for crypto operations; default to `package:cryptography`.
4. **Layered architecture**: QUIC core independent of HTTP/3, WebTransport, libp2p.
5. **Correctness first**: RFC conformance and interoperability over raw performance.
6. **Testable without network**: Protocol engine should be testable with mock I/O.
7. **Idiomatic Dart API**: Follow `dart:io` conventions (`bind`, `connect`, `Stream<List<int>>`).

---


## 7. References

- dart-lang/sdk#38595: https://github.com/dart-lang/sdk/issues/38595
- Dart RawDatagramSocket: https://api.dart.dev/stable/dart-io/RawDatagramSocket-class.html
- package:cryptography: https://pub.dev/packages/cryptography
- package:pointycastle: https://pub.dev/packages/pointycastle
- Cronet for Dart: https://pub.dev/packages/cronet_http
- pure_dart_quic: https://pub.dev/packages/pure_dart_quic

---

<!-- SOURCE: doc/research/LIBP2P_QUIC_SPEC_NOTES.md -->

---
title: "libp2p QUIC Specification Notes"
category: research
companion_rfcs: []
---

# libp2p QUIC Specification Notes


---

## 1. Purpose

libp2p QUIC transport has subtle differences from standard QUIC-self-signed certificates, peer ID derivation, mandatory mutual TLS, and /quic-v1 multiaddrs. Building quic_lib without internalizing these differences would produce a stack that speaks RFC 9000 but cannot join the IPFS network. These notes capture the libp2p-specific requirements that shape the adapter design.

## 2. Abstract

libp2p uses QUIC as a transport that combines encryption, authentication, and stream multiplexing into a single protocol. The libp2p QUIC transport eliminates the need for a separate security handshake (Noise) and stream multiplexer (mplex/yamux) â€” QUIC provides both natively.

---


## 3. Architecture: libp2p over QUIC

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚   Application Protocol  â”‚  (e.g., Bitswap, Kademlia, GossipSub)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚   libp2p Streams        â”‚  (bidirectional, multiplexed)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚   QUIC Transport        â”‚  (RFC 9000 streams = libp2p streams)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚   TLS 1.3 (in QUIC)    â”‚  (peer authentication via certificate extension)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚   UDP                   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

Key insight: libp2p streams map **directly** to QUIC bidirectional streams. No additional framing (unlike TCP transport which needs Noise + yamux/mplex).

---


## 4. Multiaddr Format

### Standard QUIC v1

```
/ip4/<IPv4>/udp/<port>/quic-v1
/ip6/<IPv6>/udp/<port>/quic-v1
```

Examples:
```
/ip4/192.168.1.1/udp/4001/quic-v1
/ip6/::1/udp/4001/quic-v1
```

### With Peer ID

```
/ip4/192.168.1.1/udp/4001/quic-v1/p2p/QmPeerID...
```

### Legacy (draft-29)

```
/ip4/192.168.1.1/udp/4001/quic
```

The `quic` code point refers to draft-29; `quic-v1` refers to RFC 9000. Implementations SHOULD support `quic-v1` and MAY support `quic` for backward compatibility.

---


## 5. TLS 1.3 with Peer Authentication (tls/tls.md)

### Overview

libp2p uses standard TLS 1.3 but with a custom peer authentication mechanism. Instead of relying on a Certificate Authority (CA), peers embed their libp2p public key in a self-signed X.509 certificate extension.

### Certificate Structure

1. **Self-signed X.509 certificate** with:
   - Subject: Can be anything (typically empty or a placeholder)
   - Public key: A newly generated key pair (NOT the host key)
   - Validity: Short-lived (recommended: current time Â± some margin)
   - Extension: `libp2p Public Key Extension`

2. **libp2p Public Key Extension** (OID: 1.3.6.1.4.1.53594.1.1):
   ```
   SignedKey {
     public_key: PublicKey,     // libp2p public key (protobuf-encoded)
     signature: bytes           // signature over "libp2p-tls-handshake:" + cert_public_key
   }
   ```

### Authentication Flow

```
Client                                    Server
  |                                         |
  |  1. Generate ephemeral key pair         |
  |  2. Create self-signed cert with        |
  |     libp2p extension (host key signed)  |
  |                                         |
  |--- TLS ClientHello --------------------->|
  |                                         |
  |<--- TLS ServerHello + Certificate ------|
  |     (contains server's libp2p ext)      |
  |                                         |
  |--- TLS Certificate ------------------->|
  |     (contains client's libp2p ext)      |
  |                                         |
  |--- TLS Finished ----------------------->|
  |<--- TLS Finished ----------------------|
  |                                         |
  |  3. Both sides verify:                  |
  |     - Certificate signature valid       |
  |     - Extension signature valid         |
  |     - Derived Peer ID matches expected  |
```

### Verification Steps

1. Verify the X.509 certificate is self-signed and structurally valid.
2. Extract the `libp2p Public Key Extension`.
3. Verify the signature in the extension covers `"libp2p-tls-handshake:" || cert_public_key_DER`.
4. Derive the Peer ID from the extracted public key.
5. (Client only) Verify the derived Peer ID matches the expected peer (from the multiaddr).

### Supported Key Types

| Key Type | Multihash Code | Notes |
|----------|---------------|-------|
| Ed25519 | 0x1300 | Preferred; identity multihash if <= 42 bytes |
| Secp256k1 | 0xe7 | Used by Ethereum nodes |
| ECDSA (P-256) | 0x1200 | Standard NIST curve |
| RSA | 0x1205 | Legacy; >= 2048 bits |

---


## 6. ALPN (Application-Layer Protocol Negotiation)

libp2p QUIC uses the ALPN token: `"libp2p"`

This is sent during the TLS handshake to identify the connection as a libp2p connection.

---


## 7. Stream Mapping

| libp2p Concept | QUIC Mechanism |
|----------------|---------------|
| libp2p stream | QUIC bidirectional stream |
| Stream open | Open new QUIC bidi stream |
| Stream close | FIN on the QUIC stream |
| Stream reset | RESET_STREAM frame |
| Muxer negotiation | Not needed (QUIC provides natively) |

### Protocol Negotiation on Streams

Each libp2p stream still uses multistream-select (or its successor) for protocol negotiation:

```
[QUIC stream opens]
Client: /multistream/1.0.0\n
Server: /multistream/1.0.0\n
Client: /ipfs/bitswap/1.2.0\n
Server: /ipfs/bitswap/1.2.0\n
[application data]
```

---


## 8. NAT Traversal Considerations

- **UDP hole punching**: libp2p defines a hole-punching protocol (Circuit Relay v2 + DCUtR) that works with QUIC.
- **Connection migration**: QUIC's connection migration can maintain connections across NAT rebinding.
- **Relay**: libp2p Circuit Relay can tunnel QUIC connections through relay nodes.

---


## 9. Differences from Standard QUIC/TLS Usage

| Aspect | Standard QUIC | libp2p QUIC |
|--------|---------------|-------------|
| Certificate validation | CA-based chain | Self-signed + extension verification |
| Server identity | DNS name in certificate | Peer ID derived from public key |
| ALPN | Application-specific (e.g., "h3") | `"libp2p"` |
| Client authentication | Optional | Mandatory (mutual TLS) |
| Stream usage | Application-defined | multistream-select negotiation per stream |
| Unidirectional streams | Used by HTTP/3 | Generally not used |

---


## 10. Relevance to quic_lib

1. **Custom TLS verifier**: Must implement a TLS certificate verifier that:
   - Accepts self-signed certificates.
   - Parses the libp2p Public Key Extension.
   - Verifies the extension signature.
   - Derives and validates the Peer ID.
2. **Certificate generation**: Must generate ephemeral certificates with the extension.
3. **ALPN configuration**: Set ALPN to `"libp2p"` for libp2p connections.
4. **Mutual TLS**: Both client and server must present certificates.
5. **Key type support**: At minimum Ed25519; ideally also Secp256k1 and ECDSA.
6. **Multiaddr parsing**: Parse `/udp/.../quic-v1` multiaddr format.
7. **No Noise/mplex**: The QUIC transport replaces both the security layer and the muxer.
8. **Dart crypto**: Use `package:cryptography` for Ed25519, `package:pointycastle` for Secp256k1/ECDSA.

---


## 11. References

- libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
- libp2p QUIC: https://libp2p.io/docs/quic/
- libp2p Addressing: https://github.com/libp2p/specs/blob/master/addressing/README.md
- libp2p Peer ID: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
- Multiaddr: https://multiformats.io/multiaddr/

---

<!-- SOURCE: doc/research/PRIOR_ART_ANALYSIS.md -->

---
title: "Prior Art Analysis: Existing QUIC Implementations"
category: research
companion_rfcs: []
---

# Prior Art Analysis: Existing QUIC Implementations


## 1. Purpose

Studying existing implementations helps quic_lib adopt proven patternsâ€”event-driven engines, pluggable congestion control, zero-copy pathsâ€”and avoid mistakes already identified in other languages.

## 2. Overview

This document surveys major QUIC implementations across languages and evaluates their architecture, maturity, and lessons for a pure-Dart implementation.

---


## 3. Implementation Matrix

| Implementation | Language | License | RFC Version | HTTP/3 | WebTransport | Stream Scheduling | Maturity |
|---------------|----------|---------|-------------|--------|--------------|-------------------|----------|
| **quic-go** | Go | MIT | RFC 9000 | Yes | Yes | Round-Robin | Production |
| **aioquic** | Python | BSD-3 | RFC 9000 | Yes | Yes | Sequential | Production |
| **picoquic** | C | BSD-2 | RFC 9000 (partial) | Yes | No | Sequential | Research/Ref |
| **MsQuic** | C | MIT | RFC 9000 | Via HTTP.sys | No | Custom | Production |
| **ngtcp2** | C | MIT | RFC 9000 | Via nghttp3 | No | Sequential | Production |
| **Chromium QUIC** | C++ | BSD-3 | RFC 9000 | Yes | Yes | Priority-based | Production |
| **quiche** (Cloudflare) | Rust | BSD-2 | RFC 9000 | Yes | No | Custom | Production |
| **quinn** | Rust | MIT/Apache-2 | RFC 9000 | Via h3 crate | No | Custom | Production |
| **pure_dart_quic** | Dart | â€” | RFC 9000 | Basic | Basic | N/A | Experimental |

---


## 4. Detailed Analysis

### 1. quic-go (Go)

**Repository**: https://github.com/quic-go/quic-go  
**Stars**: ~10k | **Active**: Yes

**Architecture**:
- Single-threaded per connection (Go goroutines).
- Clean separation: `internal/` for wire format, `quic/` for public API.
- QPACK implementation in a separate `qpack` package.
- Supports HTTP/3 via `http3` package.
- WebTransport support built atop HTTP/3.

**Key Design Decisions**:
- Uses Go's `net.PacketConn` for UDP I/O.
- Congestion control abstracted behind an interface (supports NewReno, CUBIC).
- TLS via Go's `crypto/tls` (modified fork for QUIC-specific APIs).
- Connection migration supported.

**Lessons for Dart**:
- Clean public API: `quic.Dial()`, `quic.Listen()`, `quic.Stream` â€” minimal surface.
- Goroutine-per-stream model maps well to Dart's async/await + isolates.
- Separate HTTP/3 from QUIC core.

---

### 2. aioquic (Python)

**Repository**: https://github.com/aiortc/aioquic  
**Stars**: ~2k | **Active**: Yes

**Architecture**:
- Built on Python asyncio.
- Core protocol engine in pure Python; crypto via `cryptography` library.
- Separation: `quic/` (transport), `h3/` (HTTP/3), `tls/` (handshake).
- Event-driven: protocol emits events, application handles them.

**Key Design Decisions**:
- Event/callback model: `QuicConnection.receive_datagram()` â†’ events.
- No threads; single event loop (like Dart's event loop).
- TLS 1.3 implementation included (not using OpenSSL for TLS records â€” only for crypto primitives).
- Used as the reference implementation for QUIC interop testing.

**Lessons for Dart**:
- Pure-language TLS is feasible (aioquic does TLS in Python with C crypto backend).
- Event-driven architecture maps perfectly to Dart Streams.
- Being a reference impl for interop is valuable for testing.
- Performance is secondary to correctness in the spec stage.

---

### 3. picoquic (C)

**Repository**: https://github.com/nicoquic/picoquic  
**Stars**: ~500 | **Active**: Yes

**Architecture**:
- Single C library; minimal dependencies (picotls for TLS).
- Designed as a test and experimentation platform.
- Clean state machine design.

**Key Design Decisions**:
- Callback-based API.
- Integrated congestion control experiments (BBR, CUBIC, NewReno).
- Extensive logging for protocol analysis.
- Used in QUIC interop runner.

**Lessons for Dart**:
- State machine approach for connection/stream lifecycle is clean and testable.
- Extensive logging from day one aids debugging.
- Interop test compatibility should be a goal.

---

### 4. MsQuic (C)

**Repository**: https://github.com/microsoft/msquic  
**Stars**: ~4k | **Active**: Yes (Microsoft)

**Architecture**:
- Cross-platform (Windows, Linux, macOS).
- Highly optimized for Windows kernel integration.
- Async I/O model.
- Used by Windows HTTP stack, .NET, and Edge.

**Key Design Decisions**:
- Platform-specific optimizations (Windows kernel bypass, io_uring on Linux).
- Schannel (Windows) or OpenSSL (Linux) for TLS.
- Connection pooling and load balancing built in.
- Designed for high-throughput server scenarios.

**Lessons for Dart**:
- Platform-specific optimizations are out of scope for pure Dart.
- Connection pooling and load balancing are important for production use.
- Demonstrates that QUIC can serve as a general-purpose transport (not just HTTP/3).

---

### 5. ngtcp2 (C)

**Repository**: https://github.com/ngtcp2/ngtcp2  
**Stars**: ~1k | **Active**: Yes

**Architecture**:
- Library-only (no I/O â€” user provides send/recv callbacks).
- Crypto backend abstracted (supports OpenSSL, GnuTLS, wolfSSL, boringSSL).
- HTTP/3 via separate `nghttp3` library.

**Key Design Decisions**:
- Zero-copy design philosophy.
- No I/O opinions â€” pure protocol engine.
- Excellent separation of concerns.

**Lessons for Dart**:
- Separating I/O from protocol logic is excellent architecture.
- A pure protocol engine can be tested without a network.
- Crypto backend abstraction allows flexibility.

---

### 6. Chromium QUIC (C++)

**Architecture**:
- Deeply integrated into Chromium network stack.
- Priority-based stream scheduling (mirrors HTTP/2 priority tree).
- WebTransport native support.
- BBRv2 congestion control.

**Lessons for Dart**:
- Real-world browser requirements drive features (WebTransport, priority, 0-RTT).
- Demonstrates the full stack from QUIC to WebTransport.
- Too tightly coupled to Chromium to serve as a reference â€” but useful for correctness comparison.

---

### 7. pure_dart_quic (Dart)

**Repository**: https://github.com/KellyKinyama/pure-dart-quic  
**Published**: pub.dev (0.x)

**Architecture**:
- Single package; includes QUIC, TLS 1.3, HTTP/3, WebTransport.
- Uses `RawDatagramSocket` for UDP I/O.
- Initial secret derivation, packet protection, CRYPTO frame exchange.
- Basic QPACK and HTTP/3 settings.

**Key Observations**:
- Proves feasibility of pure-Dart QUIC.
- Demonstrates `RawDatagramSocket` usage pattern.
- Appears to be a proof-of-concept; not production-ready.
- Missing: congestion control, connection migration, full stream lifecycle, comprehensive error handling.

**Lessons for quic_lib**:
- `RawDatagramSocket` is the correct Dart API for UDP.
- TLS 1.3 in pure Dart is achievable (with crypto primitives from a native-backed library).
- The primary challenge is completeness and correctness, not feasibility.

---


## 5. Architectural Patterns Across Implementations

### Common Layering

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Application     â”‚  (HTTP/3, WebTransport, libp2p)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Stream Manager  â”‚  (multiplex, flow control, scheduling)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Loss & CC       â”‚  (detection, recovery, congestion)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  Packet I/O      â”‚  (encryption, decryption, framing)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  TLS Engine      â”‚  (handshake, key derivation)
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  UDP Socket      â”‚  (send/receive datagrams)
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Common Design Choices

1. **Separate crypto from protocol**: All mature implementations abstract the crypto backend.
2. **Event-driven or callback-based**: Matches Dart's async model well.
3. **Per-connection state machine**: Explicit states for handshake, established, closing, closed.
4. **Pluggable congestion control**: Interface-based; swap NewReno for CUBIC or BBR.
5. **Separate packet number spaces**: Tracked independently per encryption level.

---


## 6. Performance Benchmarks (from research literature)

| Sender â†’ Receiver | Throughput (Gbit/s) |
|-------------------|---------------------|
| ngtcp2 â†’ ngtcp2 | 4.17 |
| quiche â†’ quiche | 2.97 |
| quic-go â†’ quic-go | 1.32 |
| lsquic â†’ lsquic | 2.47 |
| picoquic â†’ picoquic | 2.23 |

(Source: TUM NET-2022-07 study, controlled environment)

Note: Dart's single-threaded event loop may limit raw throughput compared to C/Rust implementations, but for most application scenarios (especially P2P and client use), this is acceptable.

---


## 7. Conclusions for quic_lib Design

1. **Follow ngtcp2/aioquic pattern**: Separate protocol engine from I/O.
2. **Use Dart Streams/Futures natively**: Don't fight the language's async model.
3. **Prioritize correctness**: Use interop test suites (QUIC interop runner).
4. **Layer cleanly**: QUIC core â†’ HTTP/3 â†’ WebTransport â†’ libp2p adapter.
5. **Abstract crypto**: Allow multiple backends (package:cryptography, pointycastle, future dart:crypto).
6. **Start with NewReno**: Simple, well-understood; add CUBIC/BBR later.

---


## 8. References

- QUIC Implementations Wiki: https://github.com/quicwg/base-drafts/wiki/Implementations
- QUIC Interop Runner: https://interop.seemann.io/
- TUM Performance Study: https://www.net.in.tum.de/fileadmin/TUM/NET/NET-2022-07-1/NET-2022-07-1_10.pdf
- pure_dart_quic: https://pub.dev/packages/pure_dart_quic


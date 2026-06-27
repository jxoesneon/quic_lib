---
title: "QUIC Wire Format Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Wire Encoding"
rfc_basis:
  - "RFC 9000 Sections 12, 16, 17, 19"
dependencies:
  - "ERROR_REGISTRY.md"
  - "QUIC_DATAGRAM_SPEC.md"
  - "RFC_9000_NOTES.md"
  - "ROADMAP.md"
  - "TEST_VECTORS.md"
---

# QUIC Wire Format Specification



## 1. Purpose

Every QUIC implementation begins with the wire format: if varints, headers, or frames are encoded incorrectly, no peer will ever interoperate. This specification is the foundational contract for all other dart_quic specs, defining the exact byte sequences that the packet engine must produce and consume.

## 2. Detailed Specification
### 2.1 Variable-Length Integer Encoding (RFC 9000 Section 16)

#### 2.1.1 Format

All multi-byte integers in QUIC (except packet numbers) use a self-describing variable-length encoding:

```
+------+--------+-------------+------------------------------+
| 2MSB | Length | Usable Bits | Maximum Value                |
+------+--------+-------------+------------------------------+
| 00   | 1 byte | 6           | 63                           |
| 01   | 2 bytes| 14          | 16,383                       |
| 10   | 4 bytes| 30          | 1,073,741,823                |
| 11   | 8 bytes| 62          | 4,611,686,018,427,387,903    |
+------+--------+-------------+------------------------------+
```

#### 2.1.2 Encoding Algorithm

```
encode(value):
  if value <= 63:
    write 1 byte: value
  elif value <= 16383:
    write 2 bytes: (0x40 | (value >> 8)), (value & 0xFF)
  elif value <= 1073741823:
    write 4 bytes: (0x80 | (value >> 24)), ..., (value & 0xFF)
  else:
    write 8 bytes: (0xC0 | (value >> 56)), ..., (value & 0xFF)
```

#### 2.1.3 Decoding Algorithm

```
decode(buffer):
  first_byte = read 1 byte
  length_flag = first_byte >> 6
  value = first_byte & 0x3F
  remaining = (1 << length_flag) - 1  // 0, 1, 3, or 7 more bytes
  for i in 0..remaining:
    value = (value << 8) | read_byte()
  return value
```

---


### 2.2 Packet Headers

#### 2.2.1 Header Form Bit

The first bit of the first byte determines the header type:
- `1` → Long Header
- `0` → Short Header

#### 2.2.2 Long Header Format (RFC 9000 Section 17.2)

Used during handshake (Initial, Handshake, 0-RTT) and Retry.

```
Long Header Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2),
  Type-Specific Bits (4),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Type-Specific Payload (..)
}
```

#### Long Packet Types

| Value | Type | Type-Specific Payload |
|-------|------|----------------------|
| 0x00 | Initial | Token Length (i), Token (..), Length (i), Packet Number (8..32), Payload |
| 0x01 | 0-RTT | Length (i), Packet Number (8..32), Payload |
| 0x02 | Handshake | Length (i), Packet Number (8..32), Payload |
| 0x03 | Retry | Retry Token (..), Retry Integrity Tag (128) |

#### 2.2.3 Short Header Format (RFC 9000 Section 17.3)

Used for 1-RTT (application data) packets after handshake completion.

```
Short Header Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved Bits (2),
  Key Phase (1),
  Packet Number Length (2),
  Destination Connection ID (0..160),
  Packet Number (8..32),
  Payload (..)
}
```

#### 2.2.4 Version Negotiation Packet (RFC 9000 Section 17.2.1)

```
Version Negotiation {
  Header Form (1) = 1,
  Unused (7),
  Version (32) = 0x00000000,
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Supported Versions (32) * N
}
```

#### 2.2.5 Packet Number Encoding (RFC 9000 Section 17.1)

Packet numbers are encoded in 1-4 bytes. The number of bytes is indicated by the Packet Number Length field (2 bits in the header):

| Encoded Length | Bits | Value Range |
|---------------|------|-------------|
| 1 byte | 00 | 0..255 |
| 2 bytes | 01 | 0..65535 |
| 3 bytes | 10 | 0..16777215 |
| 4 bytes | 11 | 0..4294967295 |

Decoding requires the receiver to reconstruct the full packet number from the truncated value using the largest acknowledged packet number.

**Packet Number Reconstruction Algorithm (RFC 9000 Section 17.1):**

Given:
- `truncated`: the truncated packet number from the header (1-4 bytes).
- `numBits`: the bit-length of the truncated field (determined by header type).
- `largestAcked`: the highest packet number acknowledged in the same space.

```
candidate = largestAcked + 1
clearBits = candidate & ~((1 << numBits) - 1)
reconstructed = clearBits | truncated

// Ensure the reconstructed value is within half the range of `numBits`
if reconstructed <= largestAcked - (1 << (numBits - 1)):
    reconstructed += (1 << numBits)
elif reconstructed > largestAcked + (1 << (numBits - 1)):
    reconstructed -= (1 << numBits)
```

The reconstructed value is the full packet number.

---


### 2.3 Frame Types (RFC 9000 Section 19)

#### 2.3.1 Frame Format

```
Frame {
  Type (i),       // variable-length integer
  Frame-specific fields (..)
}
```

#### 2.3.2 PADDING Frame (Type 0x00)

```
PADDING { }  // single zero byte; no fields
```

#### 2.3.3 PING Frame (Type 0x01)

```
PING { }  // no fields; used to elicit ACK
```

#### 2.3.4 ACK Frame (Types 0x02-0x03)

```
ACK {
  Largest Acknowledged (i),
  ACK Delay (i),            // microseconds, scaled by ack_delay_exponent
  ACK Range Count (i),
  First ACK Range (i),      // packets before Largest Acknowledged
  ACK Ranges (..) {         // repeated ACK Range Count times
    Gap (i),
    ACK Range Length (i)
  },
  [ECN Counts] {            // only if type == 0x03
    ECT0 Count (i),
    ECT1 Count (i),
    CE Count (i)
  }
}
```

#### 2.3.5 RESET_STREAM Frame (Type 0x04)

```
RESET_STREAM {
  Stream ID (i),
  Application Protocol Error Code (i),
  Final Size (i)
}
```

#### 2.3.6 STOP_SENDING Frame (Type 0x05)

```
STOP_SENDING {
  Stream ID (i),
  Application Protocol Error Code (i)
}
```

#### 2.3.7 CRYPTO Frame (Type 0x06)

```
CRYPTO {
  Offset (i),
  Length (i),
  Crypto Data (..)
}
```

#### 2.3.8 NEW_TOKEN Frame (Type 0x07)

```
NEW_TOKEN {
  Token Length (i),
  Token (..)
}
```

#### 2.3.9 STREAM Frame (Types 0x08-0x0f)

```
STREAM {
  Stream ID (i),
  [Offset (i)],    // present if OFF bit set
  [Length (i)],    // present if LEN bit set
  Stream Data (..) // FIN bit indicates end of stream
}
```

Bit flags in type byte:
- Bit 0 (0x01): FIN — stream data complete
- Bit 1 (0x02): LEN — Length field present
- Bit 2 (0x04): OFF — Offset field present

#### 2.3.10 Flow Control Frames

```
MAX_DATA (0x10) { Maximum Data (i) }
MAX_STREAM_DATA (0x11) { Stream ID (i), Maximum Stream Data (i) }
MAX_STREAMS (0x12/0x13) { Maximum Streams (i) }  // 0x12=bidi, 0x13=uni
DATA_BLOCKED (0x14) { Maximum Data (i) }
STREAM_DATA_BLOCKED (0x15) { Stream ID (i), Maximum Stream Data (i) }
STREAMS_BLOCKED (0x16/0x17) { Maximum Streams (i) }
```

#### 2.3.11 Connection ID Frames

```
NEW_CONNECTION_ID (0x18) {
  Sequence Number (i),
  Retire Prior To (i),
  Length (8),                  // 1..20
  Connection ID (8..160),
  Stateless Reset Token (128)
}

RETIRE_CONNECTION_ID (0x19) { Sequence Number (i) }
```

#### 2.3.12 Path Validation Frames

```
PATH_CHALLENGE (0x1a) { Data (64) }   // 8 random bytes
PATH_RESPONSE (0x1b) { Data (64) }    // echo of PATH_CHALLENGE
```

#### 2.3.13 CONNECTION_CLOSE Frames (Types 0x1c-0x1d)

```
CONNECTION_CLOSE {
  Error Code (i),
  [Frame Type (i)],           // only for type 0x1c (QUIC layer)
  Reason Phrase Length (i),
  Reason Phrase (..)
}
```
- Type 0x1c: QUIC transport error (includes offending frame type)
- Type 0x1d: Application error (no frame type field)

#### 2.3.14 HANDSHAKE_DONE Frame (Type 0x1e)

```
HANDSHAKE_DONE { }  // no fields; server-only
```

---


### 2.4 Coalesced Packets (RFC 9000 Section 12.2)

Multiple QUIC packets can be coalesced into a single UDP datagram:
- All packets in a datagram share the same 5-tuple.
- Long header packets include a Length field, enabling parsing of boundaries.
- A short header packet must be the last in the datagram (no Length field).
- Common pattern: Initial + Handshake + 0-RTT in one datagram.

---



## 3. Acceptance Criteria

- [ ] Variable-length integer encode/decode round-trips for all boundary values (0, 63, 64, 16383, 16384, 1073741823, 1073741824, max).
- [ ] Long header parsing handles all four packet types.
- [ ] Short header parsing correctly extracts DCID using known CID length.
- [ ] All 20+ frame types parse and serialize correctly.
- [ ] Packet number reconstruction from truncated encoding works for all window sizes.
- [ ] Coalesced packet splitting correctly identifies packet boundaries.
- [ ] Version Negotiation packet parsing and generation.
- [ ] Fuzz testing: random byte sequences do not cause panics/exceptions.

---


## 4. Security Considerations

- Malformed packets must be discarded without crashing.
- Buffer overread protection: always validate Length fields before accessing payload.
- Connection IDs from untrusted sources must be bounds-checked (max 20 bytes).
- Frame type parsing must handle unknown types gracefully (skip by length if available, close connection otherwise per RFC 9000 Section 12.4).

---


## 5. Dependencies

- None (pure codec, no crypto or I/O required).

---




## Used By

- [ERROR_REGISTRY.md](ERROR_REGISTRY.md) — Defines CONNECTION_CLOSE frame types and varint encoding.
- [QUIC_DATAGRAM_SPEC.md](QUIC_DATAGRAM_SPEC.md) — Frame parsing/serialization for varints and frame types.
- [../research/RFC_9000_NOTES.md](../research/RFC_9000_NOTES.md) — Research notes reference QUIC_WIRE_SPEC for complete frame type reference.
- [ROADMAP.md](ROADMAP.md) — Lists QUIC_WIRE_SPEC as a formal specification deliverable.
- [TEST_VECTORS.md](TEST_VECTORS.md) — Wire-format test vectors for varint and packet encoding.
## 6. Testing Strategy

- Unit tests for every encode/decode pair.
- RFC 9000 Appendix A test vectors for packet construction.
- Property-based testing: `encode(decode(bytes)) == bytes` for valid inputs.
- Interop: Parse packet captures from quic-go, aioquic, ngtcp2.

---


## 7. References

- RFC 9000 Section 12 (Packets and Frames): https://www.rfc-editor.org/rfc/rfc9000#section-12
- RFC 9000 Section 16 (Variable-Length Integers): https://www.rfc-editor.org/rfc/rfc9000#section-16
- RFC 9000 Section 17 (Packet Formats): https://www.rfc-editor.org/rfc/rfc9000#section-17
- RFC 9000 Section 19 (Frame Types): https://www.rfc-editor.org/rfc/rfc9000#section-19
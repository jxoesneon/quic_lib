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

HPACK requires in-order delivery of compressed field sections because the dynamic table is updated implicitly by each encoded section. In HTTP/2 over TCP, this ordering is guaranteed. In HTTP/3 over QUIC, streams are delivered independently — HPACK would cause head-of-line blocking at the application layer.

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

See [HTTP3_SPEC.md §5](../specs/HTTP3_SPEC.md#5-qpack-codec-rfc-9204) for the complete QPACK specification including static table, dynamic table, and encoder/decoder instructions. Briefly:

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


## 13. Relevance to dart_quic

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
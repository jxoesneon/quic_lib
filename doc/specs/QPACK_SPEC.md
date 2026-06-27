---
title: "QPACK Codec Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "QPACK"
rfc_basis:
  - "RFC 9204"
dependencies:
  - "HTTP3_SPEC.md"
  - "ERROR_REGISTRY.md"
  - "ROADMAP.md"
---

# QPACK Codec Specification



## 1. Purpose

Reliable QPACK implementation is required for HTTP/3 interop. HTTP/3 cannot reuse HPACK because QUIC streams are delivered out of order; QPACK eliminates head-of-line blocking by decoupling dynamic table updates from individual stream header blocks. Without a specified QPACK codec, dart_quic would be unable to compress or decompress HTTP field sections, breaking interoperability with every HTTP/3 peer.



## 2. Overview

QPACK is a header compression mechanism derived from HPACK, redesigned for HTTP/3 over QUIC. It uses two lookup tables to replace literal field names and values with compact integer indices.

```
┌─────────────────────────────┐
│     HTTP/3 Frame Layer      │  // HEADERS frames carry Encoded Field Sections
├─────────────────────────────┤
│       QPACK Codec            │  // Encoder / Decoder
├─────────────┬───────────────┤
│   Static    │   Dynamic     │  // 99 predefined entries vs. connection-built table
│   Table     │   Table       │
├─────────────┴───────────────┤
│   Encoder Stream (0x02)     │  // Instructions: insert, duplicate, set capacity
│   Decoder Stream (0x03)     │  // Instructions: ack, cancel, increment count
└─────────────────────────────┘
```

Key architectural properties:

- **Encoder/decoder separation**: Each peer has its own encoder (sending on stream type `0x02`) and decoder (receiving from peer's `0x02` stream, acknowledging on its own `0x03` stream).
- **Static table**: Immutable 99-entry table shared by all QPACK implementations (RFC 9204 Appendix A).
- **Dynamic table**: Mutable table built over the lifetime of the connection via encoder instructions; entries are referenced by absolute or relative indices.
- **Blocking resilience**: Streams may reference dynamic table entries not yet acknowledged; the decoder buffers blocked streams until the required insert count arrives.



## 3. Static Table

The static table contains 99 predefined entries (RFC 9204 Appendix A). All entries have a fixed index for the lifetime of the connection. Values may be empty (length 0). The QPACK static table is indexed from `0`; this differs from HPACK, which is indexed from `1`.

An invalid static table index encountered in a field line representation MUST be treated as a connection error of type `QPACK_DECOMPRESSION_FAILED` (`0x0200`). If received on the encoder stream, it MUST be treated as `QPACK_ENCODER_STREAM_ERROR` (`0x0201`).

The first 20 entries are listed below as a reference sample; the complete 99-entry table is defined in RFC 9204 Appendix A and must be included verbatim in any implementation:

| Index | Name | Value |
|-------|------|-------|
| 0 | `:authority` | *(empty)* |
| 1 | `:path` | `/` |
| 2 | `age` | `0` |
| 3 | `content-disposition` | *(empty)* |
| 4 | `content-length` | `0` |
| 5 | `cookie` | *(empty)* |
| 6 | `date` | *(empty)* |
| 7 | `etag` | *(empty)* |
| 8 | `if-modified-since` | *(empty)* |
| 9 | `if-none-match` | *(empty)* |
| 10 | `last-modified` | *(empty)* |
| 11 | `link` | *(empty)* |
| 12 | `location` | *(empty)* |
| 13 | `referer` | *(empty)* |
| 14 | `set-cookie` | *(empty)* |
| 15 | `:method` | `CONNECT` |
| 16 | `:method` | `DELETE` |
| 17 | `:method` | `GET` |
| 18 | `:method` | `HEAD` |
| 19 | `:method` | `OPTIONS` |



## 4. Dynamic Table

### 4.1 Capacity and Size

The dynamic table has a configurable **capacity** measured in octets. The capacity bounds the total amount of name+value bytes that can be stored, plus an overhead of 32 octets per entry. An encoder changes capacity via the *Set Dynamic Table Capacity* instruction.

```
dynamic_table_size = sum_over_entries(entry_name_length + entry_value_length + 32)
```

- The capacity MUST NOT exceed the maximum table capacity signaled by the peer via `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
- When capacity is reduced, entries are evicted from the tail (oldest first) until `dynamic_table_size <= capacity`.

### 4.2 Maximum Table Capacity

The decoder advertises its maximum acceptable dynamic table capacity through HTTP/3 SETTINGS (see [HTTP3_SPEC.md](HTTP3_SPEC.md) §2.3.4). The encoder MUST NOT set a capacity larger than this limit. An encoder MAY choose a smaller capacity at any time.

### 4.3 Insertions and Evictions

Entries are added to the dynamic table via:

- **Insert With Name Reference**
- **Insert With Literal Name**
- **Duplicate**

An entry becomes **evictable** only after:
1. The insertion has been acknowledged by the decoder (via `Insert Count Increment` or `Section Acknowledgment`), **and**
2. There are no outstanding references to the entry in unacknowledged encoded field sections.

If the encoder needs to insert a new entry but all existing entries are non-evictable, the insertion MUST NOT proceed. This prevents the encoder from evicting entries that the decoder still needs.

### 4.4 Indexing Schemes

| Index Type | Description |
|------------|-------------|
| **Absolute Index** | Monotonically increasing counter starting at 0 for the first inserted entry. Never reused after eviction. |
| **Relative Index** | Offset from the *Base* toward older entries. `relative_index = base - 1 - absolute_index`. |
| **Post-Base Index** | Offset from the *Base* toward newer entries. `post_base_index = absolute_index - base`. |



## 5. Encoder Instructions

Encoder instructions are sent on the QPACK encoder stream (unidirectional stream type `0x02`). They modify the decoder's dynamic table.

### 5.1 Set Dynamic Table Capacity

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 1 |   Capacity (5+)   |
+---+---+---+-------------------+
```

- Starts with `001` 3-bit pattern.
- `Capacity`: new dynamic table capacity, integer with 5-bit prefix.
- MUST NOT exceed `SETTINGS_QPACK_MAX_TABLE_CAPACITY` advertised by the peer.

### 5.2 Insert With Name Reference

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 1 | T |    Name Index (6+)    |
+---+---+-----------------------+
| H |     Value Length (7+)     |
+---+---------------------------+
|  Value String (Length bytes)  |
+-------------------------------+
```

- Starts with `1` 1-bit pattern.
- `T` = 0: name from static table; `T` = 1: name from dynamic table.
- `Name Index`: index of the existing entry whose name is reused.
- `H`: 1 if value is Huffman-encoded, 0 otherwise.
- Inserts a new dynamic table entry with the referenced name and supplied value.

### 5.3 Insert With Literal Name

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 1 | H | Name Length (5+)  |
+---+---+---+-------------------+
|  Name String (Length bytes)   |
+---+---------------------------+
| H |     Value Length (7+)     |
+---+---------------------------+
|  Value String (Length bytes)  |
+-------------------------------+
```

- Starts with `01` 2-bit pattern.
- Name and value are transmitted as string literals.
- Inserts a new dynamic table entry with the literal name and value.

### 5.4 Duplicate

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 |    Index (5+)     |
+---+---+---+-------------------+
```

- Starts with `000` 3-bit pattern.
- `Index`: relative index of an existing dynamic table entry.
- Creates a new entry with the same name and value as the referenced entry.



## 6. Decoder Instructions

Decoder instructions are sent on the QPACK decoder stream (unidirectional stream type `0x03`). They inform the encoder of the decoder's state.

### 6.1 Section Acknowledgment

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 1 |      Stream ID (7+)       |
+---+---------------------------+
```

- Starts with `1` 1-bit pattern.
- Acknowledges that the decoder has successfully processed the encoded field section on the given stream ID.
- Allows the encoder to mark referenced dynamic table entries as evictable.

### 6.2 Stream Cancellation

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 1 |     Stream ID (6+)    |
+---+---+-----------------------+
```

- Starts with `01` 2-bit pattern.
- Signals that the decoder has abandoned processing the given stream (e.g., stream reset).
- Allows the encoder to release any references held for that stream.

### 6.3 Insert Count Increment

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
| 0 | 0 |     Increment (6+)    |
+---+---+-----------------------+
```

- Starts with `00` 2-bit pattern.
- `Increment`: number of additional dynamic table insertions the decoder has processed.
- Increases the encoder's *Known Received Count*, making earlier entries evictable.



## 7. Encoded Field Section

Each HEADERS frame (see [HTTP3_SPEC.md](HTTP3_SPEC.md) §2.3.2) contains a single Encoded Field Section. The section begins with a prefix followed by a sequence of field line representations.

### 7.1 Encoded Field Section Prefix

```
  0   1   2   3   4   5   6   7
+---+---+---+---+---+---+---+---+
|   Required Insert Count (8+)  |
+---+---------------------------+
| S |      Delta Base (7+)      |
+---+---------------------------+
```

- **Required Insert Count**: the smallest dynamic table insert count needed to decode any dynamic table reference in this field section. If the decoder has processed fewer insertions, the stream is **blocked** until the encoder stream catches up.
- **S (Sign)**: indicates whether Delta Base is positive or negative.
- **Delta Base**: encoded as a sign bit and a 7-bit prefix integer. `Base = Required Insert Count + Delta Base` when `S = 0`; `Base = Required Insert Count - Delta Base - 1` when `S = 1`.

### 7.2 Field Line Representations

After the prefix, the field section contains one or more of the following representations:

| Representation | Prefix | Description |
|----------------|--------|-------------|
| **Indexed Field Line** | `1` `T` + index | Full name and value from static (`T=0`) or dynamic (`T=1`) table. |
| **Indexed Field Line with Post-Base Index** | `0001` + index | References dynamic table entry at or after Base. |
| **Literal Field Line with Name Reference** | `01` `N` `T` + index | Name from table; literal value. `N=1` if name should not be indexed. |
| **Literal Field Line with Post-Base Name Reference** | `0000` `N` + index | Name from dynamic post-Base entry; literal value. |
| **Literal Field Line with Literal Name** | `001` `N` `H` + literals | Both name and value sent literally. |

All string literals use an 8-bit length prefix and an `H` bit indicating Huffman encoding (RFC 9204 §4.1.2).



## 8. Dart API

Following the idiomatic Dart patterns established in [DART_API_SPEC.md](DART_API_SPEC.md) §2.5 (Stream integration, async-first, zero native dependencies), the QPACK codec exposes the following QPACK-specific types:

```dart
/// Encodes HTTP field sections into QPACK byte sequences.
abstract class QpackEncoder {
  /// Current dynamic table capacity in octets.
  int get capacity;
  set capacity(int value);

  /// Known Received Count — insertions acknowledged by the peer decoder.
  int get knownReceivedCount;

  /// Encode a field section into an Encoded Field Section byte sequence.
  List<int> encodeFieldSection(List<QpackFieldLine> lines);

  /// Read encoder instructions produced by table updates.
  /// These bytes are written to the QPACK encoder stream.
  Stream<List<int>> get encoderInstructions;
}

/// Decodes QPACK-encoded field sections back into HTTP field lines.
abstract class QpackDecoder {
  /// Total dynamic table insertions processed so far.
  int get insertCount;

  /// Decode an Encoded Field Section.
  /// May return asynchronously if the section references unacknowledged inserts.
  Future<List<QpackFieldLine>> decodeFieldSection(List<int> data);

  /// Process incoming encoder instructions from the peer.
  void processEncoderInstructions(List<int> data);

  /// Emits decoder instructions (acks, cancellations, increments)
  /// to be written to the QPACK decoder stream.
  Stream<List<int>> get decoderInstructions;
}

/// A single mutable entry in the QPACK dynamic table.
class QpackDynamicTableEntry {
  final String name;
  final String value;
  final int absoluteIndex;
  bool get isEvictable;
}

/// Manages capacity, insertion, and eviction policy.
abstract class QpackDynamicTable {
  int get capacity;
  set capacity(int value);
  int get size;
  int get entryCount;
  QpackDynamicTableEntry? getEntry(int absoluteIndex);
  void insert(String name, String value);
  void duplicate(int relativeIndex);
}

/// A name-value pair representing one HTTP field line.
class QpackFieldLine {
  final String name;
  final String value;
}
```

- All classes are pure Dart; no `dart:ffi` dependencies.
- The encoder and decoder operate on `List<int>` wire bytes to remain decoupled from the QUIC stream abstraction.
- `Stream` and `Future` are used for async decoder blocking and instruction emission, consistent with DART_API_SPEC.md §2.5.3.



## 9. Acceptance Criteria

- [ ] Static table indexes 0–98 resolve to the correct name/value pairs per RFC 9204 Appendix A.
- [ ] Dynamic table insertion, duplication, and capacity update instructions serialize and parse correctly.
- [ ] Encoder evicts oldest entries when capacity reduction forces `dynamic_table_size <= capacity`.
- [ ] Decoder blocks field sections where `Required Insert Count > insertCount`; unblocks once peer encoder stream delivers sufficient instructions.
- [ ] Encoder tracks `Known Received Count` and only evicts entries that are acknowledged and unreferenced.
- [ ] Invalid static table index (>= 99) in a field line representation triggers `QPACK_DECOMPRESSION_FAILED` (`0x0200`).



## 10. Security Considerations

- **DoS via dynamic table exhaustion**: A malicious peer can force the decoder to retain large dynamic table entries by never acknowledging them. The decoder MUST enforce a hard memory limit independent of the negotiated capacity. If the limit is exceeded, the connection MUST be closed with `QPACK_DECOMPRESSION_FAILED`.
- **Memory limits**: Both encoder and decoder MUST cap the dynamic table capacity to a value bounded by `SETTINGS_QPACK_MAX_TABLE_CAPACITY`. Implementations SHOULD apply an additional implementation-level ceiling (e.g., 1 MB) to protect against peers advertising unreasonably large values.
- **Huffman bomb protection**: String literals may use Huffman encoding. A small encoded length can expand into an arbitrarily large decoded string. The decoder MUST enforce a per-string and per-field-section maximum decoded length; exceedances MUST be treated as `QPACK_DECOMPRESSION_FAILED`.
- **Information leakage via dynamic table**: Dynamic table contents can be probed by an attacker through careful reference patterns. Implementations MUST treat all dynamic table entries as sensitive and MUST NOT include them in error messages or logs.
- **Blocked stream amplification**: An attacker may open many streams referencing future dynamic table entries, causing memory pressure from blocked stream state. The encoder MUST respect `SETTINGS_QPACK_BLOCKED_STREAMS`; the decoder MUST cancel streams that block indefinitely.



## 11. References

- RFC 9204: https://www.rfc-editor.org/rfc/rfc9204
- [HTTP3_SPEC.md](HTTP3_SPEC.md): HTTP/3 frame layer, SETTINGS, and stream mapping.
- [ERROR_REGISTRY.md](ERROR_REGISTRY.md): QPACK error codes (`0x0200`, `0x0201`).
- [DART_API_SPEC.md](DART_API_SPEC.md): Dart API design principles and `dart:io` integration.



## 12. Used By

- [HTTP3_SPEC.md](HTTP3_SPEC.md) — QPACK compresses field sections inside HEADERS frames; HTTP/3 SETTINGS govern dynamic table capacity and blocked stream limits.
- [ERROR_REGISTRY.md](ERROR_REGISTRY.md) — Defines `QPACK_DECOMPRESSION_FAILED` (`0x0200`) and `QPACK_ENCODER_STREAM_ERROR` (`0x0201`) referenced in this spec.
- [ROADMAP.md](ROADMAP.md) — QPACK codec is a prerequisite for HTTP/3 header compression deliverables.

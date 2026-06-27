# QUIC Streams Specification

**Version**: 1.0-draft  
**Status**: Specification  
**RFC Basis**: RFC 9000 Sections 2, 3, 4  
**Subsystem**: Stream Multiplexing & Flow Control

---

## 1. Purpose

This document specifies the stream abstraction for `dart_quic`: stream identification, state machines, flow control (connection-level and stream-level), stream creation limits, and the mapping to Dart's async primitives.

---

## 2. Stream Identification (RFC 9000 Section 2.1)

### 2.1 Stream ID Encoding

Stream IDs are 62-bit integers (variable-length encoded). The two least-significant bits determine the stream type:

| Bits [1:0] | Initiator | Directionality |
|-----------|-----------|----------------|
| 0b00 | Client | Bidirectional |
| 0b01 | Server | Bidirectional |
| 0b10 | Client | Unidirectional |
| 0b11 | Server | Unidirectional |

### 2.2 Stream ID Sequence

- Client-initiated bidi: 0, 4, 8, 12, ...
- Server-initiated bidi: 1, 5, 9, 13, ...
- Client-initiated uni: 2, 6, 10, 14, ...
- Server-initiated uni: 3, 7, 11, 15, ...

Formula: `stream_id = type_bits + 4 * sequence_number`

---

## 3. Stream State Machine

### 3.1 Sending States (RFC 9000 Section 3.1)

```
          ┌──────────┐
          │  Ready   │  (stream created, no data sent)
          └────┬─────┘
               │ send STREAM / STREAM_DATA_BLOCKED
               ▼
          ┌──────────┐
          │   Send   │  (sending data)
          └────┬─────┘
               │ send STREAM + FIN
               ▼
          ┌──────────┐
          │Data Sent │  (all data sent, awaiting ACK)
          └────┬─────┘
               │ all data ACKed
               ▼
          ┌──────────┐
          │Data Recvd│  (terminal — success)
          └──────────┘

At any point before Data Recvd, RESET_STREAM transitions to:
          ┌───────────┐
          │Reset Sent │  (awaiting ACK of RESET_STREAM)
          └─────┬─────┘
                │ RESET_STREAM ACKed
                ▼
          ┌───────────┐
          │Reset Recvd│  (terminal — aborted)
          └───────────┘
```

### 3.2 Receiving States (RFC 9000 Section 3.2)

```
          ┌──────────┐
          │   Recv   │  (receiving data)
          └────┬─────┘
               │ recv STREAM + FIN (all data)
               ▼
          ┌───────────┐
          │Size Known │  (final size known, some data may be missing)
          └─────┬─────┘
                │ all data received
                ▼
          ┌───────────┐
          │Data Recvd │  (all data received, pending read)
          └─────┬─────┘
                │ application reads all data
                ▼
          ┌──────────┐
          │Data Read │  (terminal — success)
          └──────────┘

At any point, RESET_STREAM received transitions to:
          ┌───────────┐
          │Reset Recvd│
          └─────┬─────┘
                │ application notified
                ▼
          ┌───────────┐
          │Reset Read │  (terminal)
          └───────────┘
```

---

## 4. Flow Control (RFC 9000 Section 4)

### 4.1 Credit-Based Model

Flow control is credit-based: the receiver advertises the maximum offset (for streams) or maximum total data (for connection) the sender may use. The sender MUST NOT exceed these limits.

### 4.2 Connection-Level Flow Control

- **MAX_DATA frame**: Receiver advertises the maximum total bytes across all streams.
- **DATA_BLOCKED frame**: Sender signals it has data to send but is blocked by the connection limit.
- Limit applies to the sum of data sent on all streams.

### 4.3 Stream-Level Flow Control

- **MAX_STREAM_DATA frame**: Receiver advertises the maximum offset on a specific stream.
- **STREAM_DATA_BLOCKED frame**: Sender signals it is blocked on a stream limit.
- Each stream has an independent limit.

### 4.4 Stream Count Limits

- **MAX_STREAMS frame**: Limits the cumulative number of streams the peer can open (by type: bidi or uni).
- **STREAMS_BLOCKED frame**: Sender signals it wants to open more streams but is at the limit.
- Limits are cumulative (not concurrent) — once a stream ID is used, it counts even after close.

### 4.5 Initial Limits

Set via transport parameters during handshake:

| Parameter | Controls |
|-----------|----------|
| `initial_max_data` | Connection-level byte limit |
| `initial_max_stream_data_bidi_local` | Byte limit for locally-initiated bidi streams |
| `initial_max_stream_data_bidi_remote` | Byte limit for remotely-initiated bidi streams |
| `initial_max_stream_data_uni` | Byte limit for uni streams |
| `initial_max_streams_bidi` | Cumulative bidi stream limit |
| `initial_max_streams_uni` | Cumulative uni stream limit |

### 4.6 Flow Control Update Strategy

The receiver SHOULD send flow control updates when:
- The application has consumed significant buffered data.
- The window is approaching exhaustion.

A common strategy: send MAX_STREAM_DATA when the application has consumed half the current window.

---

## 5. Stream Operations

### 5.1 Opening a Stream

- Allocate the next stream ID of the appropriate type.
- Check against MAX_STREAMS limit; if at limit, either wait or signal STREAMS_BLOCKED.
- Initialize send and receive state machines.

### 5.2 Sending Data

- Buffer data from the application.
- Segment into STREAM frames respecting:
  - Maximum packet size.
  - Connection-level flow control.
  - Stream-level flow control.
  - Congestion window.
- Set FIN bit on the last STREAM frame.

### 5.3 Receiving Data

- Reassemble STREAM frames in order (handle gaps due to reordering).
- Deliver to application in order.
- Send MAX_STREAM_DATA as application consumes data.
- On FIN: mark stream as complete.

### 5.4 Resetting a Stream

- Sender: Send RESET_STREAM with final size and error code.
- Receiver: On RESET_STREAM, discard buffered data, signal error to application.

### 5.5 Stopping a Stream

- Receiver: Send STOP_SENDING to request sender stop.
- Sender: On STOP_SENDING, SHOULD send RESET_STREAM.

---

## 6. Dart API Mapping

### 6.1 Bidirectional Stream

```dart
abstract class QuicStream {
  int get streamId;
  bool get isLocallyInitiated;
  
  // Reading
  Stream<List<int>> get inbound;  // ordered byte stream
  
  // Writing
  StreamSink<List<int>> get outbound;
  Future<void> close();  // sends FIN
  
  // Error handling
  Future<void> reset(int errorCode);
  Future<void> stopSending(int errorCode);
  
  // State
  StreamState get sendState;
  StreamState get receiveState;
}
```

### 6.2 Unidirectional Stream

```dart
abstract class QuicSendStream {
  int get streamId;
  StreamSink<List<int>> get outbound;
  Future<void> close();
  Future<void> reset(int errorCode);
}

abstract class QuicReceiveStream {
  int get streamId;
  Stream<List<int>> get inbound;
  Future<void> stopSending(int errorCode);
}
```

### 6.3 Stream Acceptance

```dart
abstract class QuicConnection {
  Stream<QuicStream> get incomingBidirectionalStreams;
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams;
  
  Future<QuicStream> openBidirectionalStream();
  Future<QuicSendStream> openUnidirectionalStream();
}
```

---

## 7. Reassembly Buffer

### 7.1 Design

Incoming STREAM frames may arrive out of order. The reassembly buffer:
- Stores (offset, data) pairs.
- Tracks contiguous range from offset 0.
- Delivers to application only contiguous prefix.
- Enforces MAX_STREAM_DATA (total buffered <= limit).

### 7.2 Overlap Handling

If two STREAM frames overlap (same offset range), the data MUST be identical (RFC 9000 Section 2.2). If data differs, close connection with PROTOCOL_VIOLATION.

---

## 8. Priority and Scheduling

RFC 9000 does not mandate a specific scheduling algorithm. Options:

| Algorithm | Properties |
|-----------|-----------|
| Round-Robin | Fair across streams; may delay high-priority data |
| Sequential | Complete one stream before the next; good for web resources |
| Priority-based | Weighted scheduling; application-controlled |

The implementation SHOULD support priority hints from the application layer (HTTP/3 priority signals).

---

## 9. Acceptance Criteria

- [ ] Stream IDs are correctly generated for all four types.
- [ ] State machine transitions match RFC 9000 Section 3 for all paths.
- [ ] Flow control prevents sending beyond MAX_DATA / MAX_STREAM_DATA.
- [ ] STREAMS_BLOCKED is sent when stream creation limit reached.
- [ ] Reassembly buffer handles out-of-order, duplicate, and overlapping frames.
- [ ] FIN handling correctly finalizes stream data.
- [ ] RESET_STREAM properly aborts both sender and receiver.
- [ ] STOP_SENDING triggers RESET_STREAM from the sender.
- [ ] Dart Streams complete/error correctly on stream close/reset.
- [ ] Connection-level flow control aggregates across all streams.

---

## 10. Security Considerations

- **Resource exhaustion**: Limit maximum buffered data per stream and per connection.
- **Stream ID validation**: Reject frames referencing stream IDs beyond MAX_STREAMS.
- **Final size consistency**: A STREAM frame that contradicts a previously declared final size is a protocol violation.
- **Slow-read attacks**: Implementation should enforce timeouts on idle streams.

---

## 11. Dependencies

- Wire codec ([QUIC_WIRE_SPEC.md](./QUIC_WIRE_SPEC.md)): STREAM, flow control, and RESET frame parsing.
- Connection manager: Transport parameters provide initial flow control limits.

---

## 12. Testing Strategy

- State machine testing: Verify all valid transitions and reject invalid ones.
- Flow control: Verify sender respects limits; verify receiver sends updates.
- Interop: Exchange data with quic-go, aioquic streams.
- Stress: Open MAX_STREAMS concurrent streams, send data, verify delivery.
- Edge cases: Zero-length STREAM frames, FIN-only frames, maximum offset values.

---

## References

- RFC 9000 Section 2 (Streams): https://www.rfc-editor.org/rfc/rfc9000#section-2
- RFC 9000 Section 3 (Stream States): https://www.rfc-editor.org/rfc/rfc9000#section-3
- RFC 9000 Section 4 (Flow Control): https://www.rfc-editor.org/rfc/rfc9000#section-4

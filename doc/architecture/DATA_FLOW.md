# Data Flow Architecture

**Version**: 1.0-draft  
**Status**: Architecture  
**Subsystem**: Packet Processing Pipelines

---

## 1. Purpose

This document describes the data flow through `dart_quic`: the packet receive path, send path, stream demultiplexing, application read/write semantics, and the event-driven processing model.

---

## 2. High-Level Data Flow

```
                    ┌──────────────┐
                    │  Application │
                    │  (HTTP/3,    │
                    │  WebTransport│
                    │  libp2p)     │
                    └───┬──────┬───┘
                        │      │
              write()   │      │  Stream<List<int>>
                        │      │
                    ┌───▼──────▼───┐
                    │    Stream    │
                    │   Manager    │
                    └───┬──────┬───┘
                        │      │
           STREAM frames│      │ STREAM frames
                        │      │
                    ┌───▼──────▼───┐
                    │   Packet     │
                    │   Engine     │
                    │ (encrypt/    │
                    │  decrypt)    │
                    └───┬──────┬───┘
                        │      │
         UDP datagrams  │      │  UDP datagrams
                        │      │
                    ┌───▼──────▼───┐
                    │   UDP I/O    │
                    │(RawDatagram  │
                    │  Socket)     │
                    └───┬──────┬───┘
                        │      │
                        ▼      ▲
                    ═══════════════
                       Network
                    ═══════════════
```

---

## 3. Receive Path (Detailed)

### 3.1 Step-by-Step

| Step | Operation | Output |
|------|-----------|--------|
| 1. UDP Receive | `RawDatagramSocket.receive()` | raw bytes + source address |
| 2. Coalesced Split | Long Header → split by Length field; Short Header → last in datagram | `List<RawPacket>` |
| 3. Connection Lookup | Extract DCID → registry lookup; if Initial → new connection (server); else discard/stateless-reset | `(RawPacket, Connection)` |
| 4. Header Protection Removal | Determine encryption level; unmask first byte + PN bytes using `hp_key` | cleartext header |
| 5. PN Reconstruction | Truncated PN + `largest_acked` → closest full value in range | full packet number |
| 6. AEAD Decryption | `nonce = iv XOR pad_left(pn, 12)`; `AEAD-Decrypt(key, nonce, header, ciphertext)`; fail → discard silently | decrypted payload |
| 7. Frame Parsing | Parse frames by type varint from payload | `List<Frame>` |
| 8. Frame Dispatch | Route to handlers (see dispatch table below) | events to subsystems |

**Frame Dispatch Table:**

```
ACK           → Recovery.onAckReceived()
CRYPTO        → TLS.onHandshakeData()
STREAM        → StreamManager.onStreamFrame()
MAX_DATA      → FlowController.onMaxData()
MAX_STREAM_*  → FlowController.onMaxStreamData()
RESET_STREAM  → StreamManager.onResetStream()
STOP_SENDING  → StreamManager.onStopSending()
PING          → (mark as ack-eliciting)
PATH_*        → MigrationHandler.onPathFrame()
CONN_CLOSE    → ConnectionManager.onClose()
HANDSHAKE_DONE→ ConnectionManager.onHandshakeDone()
NEW_CONN_ID   → ConnectionIdManager.onNewId()
RETIRE_CONN_ID→ ConnectionIdManager.onRetire()
NEW_TOKEN     → TokenStore.onNewToken()
DATAGRAM      → DatagramHandler.onDatagram()
```

---

## 4. Send Path (Detailed)

### 4.1 Triggering Send

Sending is triggered by:
1. **Application write**: New data on a stream.
2. **Control frame needed**: ACK, flow control update, PATH_RESPONSE.
3. **Retransmission**: Lost frames detected by Recovery.
4. **PTO probe**: Timer expiry requires ack-eliciting packet.
5. **Handshake**: TLS produces handshake bytes.

### 4.2 Step-by-Step

| Step | Operation | Output |
|------|-----------|--------|
| 1. Send Opportunity | `CongestionController.canSend()` && `Pacer.canSendNow()` && `AntiAmplification.canSend()`; if no → schedule timer | permission to send |
| 2. Frame Assembly | Priority: ACK > CRYPTO > flow control > STREAM data; pad Initial to ≥1200 bytes | `List<Frame>` fitting in one packet |
| 3. Packet Construction | Choose encryption level; assign next PN; build header; serialize frames | `(header_bytes, payload_bytes, pn)` |
| 4. AEAD Encryption | `nonce = iv XOR pad_left(pn, 12)`; `AEAD-Encrypt(key, nonce, header, payload)` | `header + ciphertext` |
| 5. Header Protection | Sample 16 bytes from ciphertext → 5-byte mask (AES-ECB/ChaCha20); XOR onto first byte + PN bytes | protected packet bytes |
| 6. Coalescing (opt.) | If multiple encryption levels ready: concatenate into one UDP datagram (e.g., Initial + Handshake) | UDP payload(s) |
| 7. UDP Send + Track | `RawDatagramSocket.send()`; `SentPacketTracker.onSent(pn, now, size, frames)`; `CongestionController.onPacketSent(size)` | packet on wire + metadata |

---

## 5. Stream Demultiplexing

### 5.1 Receive Side

```
STREAM frame received
  ├── Extract stream_id
  ├── Lookup stream in StreamRegistry
  │   ├── Found → deliver to existing stream
  │   └── Not found → check if valid new stream
  │       ├── Valid → create stream, notify application via Stream<QuicStream>
  │       └── Invalid → protocol violation → close connection
  ├── ReassemblyBuffer.insert(offset, data, fin)
  ├── If contiguous data available from offset 0:
  │   └── StreamController.add(data)  → application receives via Stream
  └── Update flow control consumed bytes
```

### 5.2 Send Side

```
Application calls stream.add(data)
  ├── SendBuffer.enqueue(data)
  ├── StreamScheduler registers stream as "has data"
  ├── On next send opportunity:
  │   ├── Scheduler picks stream (round-robin / priority)
  │   ├── FlowController.availableCredit(stream) → max bytes
  │   ├── SendBuffer.dequeue(min(credit, packet_space))
  │   └── Build STREAM frame
  └── If stream.close() called: set FIN bit on last frame
```

---

## 6. ACK Processing Flow

```
ACK frame received
  │
  ├── Parse ACK ranges
  ├── Identify newly acknowledged packets
  │
  ├── RTT Update:
  │   └── If largest_acked is ack-eliciting:
  │       └── RttEstimator.update(now - sent_time, ack_delay)
  │
  ├── Congestion Control:
  │   └── For each newly acked packet:
  │       └── CongestionController.onPacketAcked(bytes)
  │
  ├── Loss Detection:
  │   ├── Check packet threshold (gap >= 3)
  │   ├── Check time threshold (too old)
  │   └── Declare lost packets
  │       └── For each lost packet:
  │           ├── CongestionController.onPacketLost(bytes)
  │           └── Retransmit frames (mark for re-send)
  │
  └── Timer Reset:
      └── Reset PTO timer based on new state
```

---

## 7. Handshake Data Flow

```
┌─────────┐                                    ┌─────────┐
│ Client  │                                    │ Server  │
└────┬────┘                                    └────┬────┘
     │                                              │
     │  TLS.start() → ClientHello bytes            │
     │  Wrap in CRYPTO frame (Initial level)        │
     │  Encrypt with Initial keys                   │
     │  Pad to 1200 bytes                          │
     │                                              │
     │──────────── Initial[CRYPTO] ────────────────>│
     │                                              │
     │                     TLS.onData(ClientHello)  │
     │                     → ServerHello bytes      │
     │                     → Install Handshake keys │
     │                     → EncExts+Cert+CV+Fin   │
     │                                              │
     │<──── Initial[CRYPTO(SH)] ───────────────────│
     │<──── Handshake[CRYPTO(EE+Cert+CV+Fin)] ────│
     │                                              │
     │  TLS.onData(ServerHello)                    │
     │  → Install Handshake keys                   │
     │  TLS.onData(EE+Cert+CV+Fin)               │
     │  → Verify certificate                       │
     │  → Install 1-RTT keys                       │
     │  → Generate Finished bytes                  │
     │                                              │
     │──── Handshake[CRYPTO(Fin)] ─────────────────>│
     │──── 1-RTT[STREAM(data)] ────────────────────>│
     │                                              │
     │                     TLS.onData(ClientFin)    │
     │                     → Install 1-RTT keys    │
     │                     → Handshake confirmed   │
     │                                              │
     │<──── 1-RTT[HANDSHAKE_DONE] ─────────────────│
     │                                              │
```

---

## 8. Timer Events

| Timer | Trigger | Action |
|-------|---------|--------|
| PTO | No ACK within PTO interval | Send probe packet |
| Idle | No activity for `max_idle_timeout` | Close connection |
| Key discard | Handshake confirmed | Discard Initial/Handshake keys |
| Pacing | Token bucket empty | Schedule next send |
| Loss time | Earliest potential loss | Re-check loss detection |

---

## 9. Dart Async Integration

### 9.1 Event Sources

```dart
// UDP receive events
socket.listen((event) {
  if (event == RawSocketEvent.read) {
    final datagram = socket.receive();
    processIncoming(datagram);
  }
});

// Timer events
Timer(ptoDuration, () => onPtoExpired());

// Application writes
streamController.stream.listen((data) {
  sendBuffer.enqueue(data);
  scheduleSend();
});
```

### 9.2 Backpressure

- If `StreamController` buffer exceeds threshold → pause upstream.
- If congestion window full → stop dequeuing from send buffers.
- If flow control exhausted → stream write Future doesn't complete until credit available.

---

## References

- [MODULE_OVERVIEW.md](./MODULE_OVERVIEW.md) (module responsibilities)
- [QUIC_WIRE_SPEC.md](../specs/QUIC_WIRE_SPEC.md) (frame/packet formats)
- [QUIC_CRYPTO_SPEC.md](../specs/QUIC_CRYPTO_SPEC.md) (encryption details)
- [QUIC_RECOVERY_SPEC.md](../specs/QUIC_RECOVERY_SPEC.md) (loss detection logic)
- [QUIC_STREAMS_SPEC.md](../specs/QUIC_STREAMS_SPEC.md) (flow control and reassembly)

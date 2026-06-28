# dart_quic Blue Team Security Audit – V2

**Auditor:** Defensive Security Engineer (Blue Team)  
**Scope:** All source files under `lib/src/`  
**Date:** 2025-01-18  
**Previous Audit:** 19 of 21 findings from V1 have been remediated.  
**Methodology:** Static source-code review focused on unbounded growth vectors, missing input validation, integer overflow/underflow, state-machine bypasses, resource exhaustion, and defense gaps.

---

## Executive Summary

The codebase has been substantially hardened since V1. The 19 previously-fixed issues (memory limits on `ReassemblyBuffer`, `ConnectionRegistry`, `MigrationHelper`, `LossDetector`, `SentPacketTracker`; `FlowController.maxWindow`; `ConnectionIdManager.maxRetiredIds`; `PtoScheduler` backoff cap; `CongestionController` overflow guards; `AntiAmplificationLimit` negative-byte rejection; `PacketNumberSpaceManager` replay window; `SentPacketTracker` ACK clamping; `RttEstimator` RTT/maxAckDelay caps; `ReceiveStateMachine` finalSize validation; `RateLimiter` utility; `ConnectionStateMachine` transition rate limiting; multiaddr error cleanup; and `AntiAmplificationLimit` wiring) are all present and effective.

However, **12 new findings** were discovered in this re-audit. The most serious is the **absence of memory limits on `CryptoFrameAssembler`**, which is structurally identical to the `ReassemblyBuffer` vulnerability fixed in V1. A malicious peer can exhaust memory by sending many out-of-order CRYPTO frames. Other issues include uncaught exceptions in coalesced-packet parsing, missing non-negative checks in `FlowController`, a state-machine validation bypass in `QuicReceiveStream`, an infinite-loop edge case in `CryptoFrameDeliverer`, and several missing input-validation or rate-limiting gaps.

**Finding Count by Severity**

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 2 |
| MEDIUM   | 4 |
| LOW      | 6 |

---

## Findings

### HIGH-1: `CryptoFrameAssembler` – Unbounded Memory Growth via CRYPTO Frame Buffering

- **File:** `lib/src/crypto/tls/crypto_frame_assembler.dart`  
- **Lines:** 1–66  
- **Category:** Resource Exhaustion / Unbounded Growth

**Description:**  
`CryptoFrameAssembler` maintains a `_buffer` Map of out-of-order CRYPTO frame data keyed by offset. Unlike `ReassemblyBuffer` (which was hardened in V1 with `maxBufferSize`, `maxFragmentCount`, and `maxOffsetGap`), the assembler has **no size, fragment, or offset-gap limits**. A malicious peer can send arbitrarily many CRYPTO frames with large offsets, causing unbounded memory growth and a memory-exhaustion DoS.

**Code Snippet:**
```dart
class CryptoFrameAssembler {
  final Map<int, List<int>> _buffer = {};   // UNBOUNDED
  int _readOffset = 0;

  List<Uint8List> deliver(CryptoFrame frame) {
    _buffer[storeOffset] = storeData;       // No eviction, no size cap
    ...
  }
}
```

**Recommendation:**  
Add the same three limits used in `ReassemblyBuffer`:
- `maxBufferSize` (e.g., 16 MB)
- `maxFragmentCount` (e.g., 1024)
- `maxOffsetGap` (e.g., 16 MB)

Throw `StateError` when any limit is exceeded, matching the defensive pattern in `ReassemblyBuffer`.

---

### HIGH-2: `CoalescedPacket` – Uncaught `RangeError` on Truncated VarInts

- **File:** `lib/src/wire/coalesced_packet.dart`  
- **Lines:** 95–103 (`_decodeVarInt`)  
- **Category:** Missing Input Validation / DoS

**Description:**  
`_decodeVarInt` reads the first byte to determine the total varint length (1, 2, 4, or 8) and then loops over the remaining bytes **without checking whether those bytes exist**:

```dart
static int _decodeVarInt(Uint8List bytes, int offset) {
  final firstByte = bytes[offset];
  final length = _varIntLength(firstByte);   // 1, 2, 4, or 8
  var value = firstByte & 0x3F;
  for (var i = 1; i < length; i++) {
    value = (value << 8) | bytes[offset + i];   // RangeError if truncated
  }
  return value;
}
```

A malformed UDP datagram containing a long-header Initial packet with a truncated token-length or payload-length varint will cause an **unhandled `RangeError`** to propagate out of `CoalescedPacket.split()` and crash the caller (`PacketReceiver.processDatagram`).

**Recommendation:**  
Either:
1. Add explicit bounds checks inside `_decodeVarInt` (return a sentinel or throw `ArgumentError` that can be caught), or
2. Wrap the `for` loop body with `if (offset + i < bytes.length)` and throw a controlled `ArgumentError('Truncated varint')`.

Ensure `split()` and `_findLongHeaderEnd()` catch the controlled exception and return `offset` ("cannot parse further").

---

### MEDIUM-1: `FlowController.consume` – Missing Non-Negative Validation

- **File:** `lib/src/streams/flow_controller.dart`  
- **Line:** 24  
- **Category:** Missing Input Validation / State Manipulation

**Description:**  
`consume(int bytes)` performs `_consumed += bytes` without validating `bytes >= 0`. Passing a negative value decreases `_consumed`, **inflating the flow-control window** and allowing a peer to receive more data than permitted.

```dart
void consume(int bytes) {
  _consumed += bytes;   // No >= 0 check
}
```

**Recommendation:**  
Add a guard:
```dart
if (bytes < 0) throw ArgumentError('bytes must be non-negative');
```

---

### MEDIUM-2: `QuicReceiveStream.deliver` – `ReceiveStateMachine` Validation Bypassed

- **File:** `lib/src/streams/quic_stream.dart`  
- **Lines:** 53–60  
- **Category:** State Machine Bypass

**Description:**  
`QuicReceiveStream.deliver` calls `_stateMachine.onDataReceived(fin: fin)` **without passing the cumulative `bytesReceived`** parameter (defaults to `0`). The `ReceiveStateMachine` performs critical `finalSize` validation based on `bytesReceived`:

```dart
// receive_state_machine.dart
void onDataReceived({bool fin = false, int? finalSize, int bytesReceived = 0}) {
  if (finalSize != null && _bytesReceived > finalSize) { ... }
}
```

Because `deliver` never updates `bytesReceived`, the check is **never triggered**, allowing a peer to send data after a FIN without the state machine detecting the protocol violation.

**Recommendation:**  
Track cumulative bytes received in `QuicReceiveStream` and pass the running total to `onDataReceived(bytesReceived: cumulative)`.

---

### MEDIUM-3: `CryptoFrameDeliverer.chunk` – Infinite Loop on `maxFrameSize <= 0`

- **File:** `lib/src/crypto/tls/crypto_frame_deliverer.dart`  
- **Lines:** 15–29  
- **Category:** Missing Input Validation / Denial of Service

**Description:**  
`chunk` lacks validation on the `maxFrameSize` parameter:

```dart
List<CryptoFrame> chunk(Uint8List message, {int maxFrameSize = 1200}) {
  while (messageOffset < message.length) {
    final end = messageOffset + maxFrameSize > message.length
        ? message.length
        : messageOffset + maxFrameSize;
    final chunk = message.sublist(messageOffset, end);
    _writeOffset += chunk.length;
    messageOffset += chunk.length;   // If maxFrameSize == 0, chunk.length == 0 → infinite loop
  }
}
```

If `maxFrameSize` is `0`, `chunk.length` is `0` and `messageOffset` never advances. If `maxFrameSize` is negative, `sublist(end < start)` throws `RangeError`.

**Recommendation:**  
```dart
if (maxFrameSize <= 0) throw ArgumentError('maxFrameSize must be positive');
```

---

### MEDIUM-4: `SentPacketTracker.onAck` – Unbounded Map Growth via Arbitrary Space Index

- **File:** `lib/src/recovery/sent_packet_tracker.dart`  
- **Lines:** 50–58  
- **Category:** Unbounded Growth

**Description:**  
The `space` parameter is not validated before use:

```dart
List<SentPacketInfo> onAck(int space, int largestAcked, ...) {
  final spaceMap = _spaces.putIfAbsent(space, () => {});   // Any int key is accepted
  ...
}
```

A caller that passes an unvalidated `spaceIndex` (e.g., derived directly from attacker-controlled input) can cause the `_spaces` Map to grow without bound.

**Recommendation:**  
Validate `space` before map access:
```dart
if (space < 0 || space > 2) throw ArgumentError('Invalid packet number space: $space');
```

---

### LOW-1: `PacketNumberSpaceManager.onReceived` – Missing Non-Negative Packet Number Validation

- **File:** `lib/src/recovery/packet_number_space.dart`  
- **Lines:** 75–103  
- **Category:** Missing Input Validation

**Description:**  
`onReceived` does not reject negative `packetNumber` values. A negative packet number passes the replay-window logic and is accepted as valid.

**Recommendation:**  
```dart
if (packetNumber < 0) return false;
```

---

### LOW-2: `LossDetector` – Missing Non-Negative Packet Number Validation

- **File:** `lib/src/recovery/loss_detector.dart`  
- **Lines:** 22–29, 33–55  
- **Category:** Missing Input Validation

**Description:**  
`onPacketSent` and `onAckReceived` accept negative packet numbers. A negative `packetNumber` stored in `_sentTimes` can later be incorrectly flagged as lost because `largestAcked - packetNumber >= packetThreshold` becomes trivially true for large positive `largestAcked`.

**Recommendation:**  
Validate `packetNumber >= 0` in both `onPacketSent` and `onAckReceived`.

---

### LOW-3: `HandshakeStateMachine` – No Rate Limiting on State Transitions

- **File:** `lib/src/crypto/tls/handshake_state_machine.dart`  
- **Lines:** 60–140  
- **Category:** Resource Exhaustion / Defense Gap

**Description:**  
Unlike `ConnectionStateMachine` (which uses `RateLimiter` to cap transitions at 100/sec), `HandshakeStateMachine` has **no transition rate limiting**. A peer that floods handshake messages can force the state machine to evaluate many transitions per second, consuming CPU.

**Recommendation:**  
Add a `RateLimiter` (reuse the existing utility in `lib/src/security/rate_limiter.dart`) to `onMessage()`.

---

### LOW-4: `PacketReceiver.processPacket` – No Per-Packet Frame Count Limit

- **File:** `lib/src/connection/packet_receiver.dart`  
- **Lines:** 40–50  
- **Category:** Resource Exhaustion

**Description:**  
The frame-parsing loop has no limit on the number of frames it will extract from a single packet:

```dart
while (offset < payload.length) {
  final (frame, newOffset) = FrameCodec.parse(payload, offset: offset);
  frames.add(frame);
  offset = newOffset;
}
```

A single packet packed with many 1-byte frames (e.g., `PADDING` frames) forces the creation of thousands of short-lived `Frame` objects.

**Recommendation:**  
Add a `maxFramesPerPacket` constant (e.g., 256) and break/throw if exceeded.

---

### LOW-5: `HeaderProtection` – Missing Bounds Check on Custom VarInt Read

- **File:** `lib/src/crypto/packet/header_protection.dart`  
- **Lines:** 189–197 (`_readVarInt`)  
- **Category:** Missing Input Validation / Defense-in-Depth

**Description:**  
`_readVarInt` is a custom varint decoder that does not validate buffer bounds before reading continuation bytes:

```dart
static int _readVarInt(Uint8List bytes, int offset) {
  final firstByte = bytes[offset];
  final length = 1 << (firstByte >> 6);
  var value = firstByte & 0x3F;
  for (var i = 1; i < length; i++) {
    value = (value << 8) | bytes[offset + i];   // RangeError if header is truncated
  }
  return value;
}
```

While the caller (`_computeLongHeaderPnOffset`) usually operates on a header that has already been validated by `PacketHeaderParser`, direct use of `HeaderProtection.remove()` on raw, unvalidated bytes could crash with an unhandled `RangeError`.

**Recommendation:**  
Replace the custom `_readVarInt` with the shared `VarInt.decode` helper (which already has bounds checks) or add explicit bounds guards.

---

### LOW-6: `UdpSocket` – Unbounded Stream Buffer for Slow Consumers

- **File:** `lib/src/io/udp_socket.dart`  
- **Lines:** 9–11, 13–25  
- **Category:** Resource Exhaustion / Defense Gap

**Description:**  
Incoming datagrams are pushed into a `StreamController.broadcast()`. If the application consumer is slower than the arrival rate, datagrams accumulate in the controller’s internal event queue without bound. There is no UDP-level rate limiter or maximum receive-buffer size enforced by the library.

**Recommendation:**  
Consider adding an application-level rate limiter or a bounded receive queue in front of the stream, or document that consumers must apply backpressure.

---

## Verified Hardened Components (No Findings)

The following components were reviewed and confirmed to contain effective defensive measures:

| Component | Defense Verified |
|-----------|-----------------|
| `ReassemblyBuffer` | `maxBufferSize=16MB`, `maxOffsetGap=16MB`, `maxFragmentCount=1024` |
| `ConnectionRegistry` | `maxConnections=65536`, CID length validation `1..20` |
| `ConnectionStateMachine` | `RateLimiter` at 100 transitions/sec |
| `ConnectionIdManager` | `maxActiveIds=8`, `maxRetiredIds=32` |
| `MigrationHelper` | `maxPendingChallenges=8`, `maxValidatedPaths=16` |
| `LossDetector` | `maxTrackedPackets=10000` |
| `SentPacketTracker` | `maxPacketsPerSpace=10000`, ACK clamping to `highestSent` |
| `CongestionController` | `maxCwnd` overflow guard, negative-byte clamping |
| `PtoScheduler` | `ptoCount` cap at 10 |
| `RttEstimator` | `maxRttUs=60s`, `maxAckDelayUs≈16s` |
| `FlowController` | `maxWindow=256MB` |
| `PacketNumberSpaceManager` | 64-packet replay bitmask window |
| `AntiAmplificationLimit` | Negative-byte rejection (`ArgumentError`) |
| `ReceiveStateMachine` | `finalSize` vs `bytesReceived` validation |
| `RateLimiter` | Sliding-window implementation |
| `multiaddr` | Error sanitization (no sensitive data in exceptions) |
| `VarInt` | `maxValue` enforcement, bounds-checked decode |

---

## Remediation Priority

1. **Immediate (HIGH)**
   - Add memory limits to `CryptoFrameAssembler`.
   - Harden `CoalescedPacket._decodeVarInt` against truncated inputs.

2. **Short-term (MEDIUM)**
   - Validate `bytes >= 0` in `FlowController.consume`.
   - Wire `bytesReceived` tracking into `QuicReceiveStream.deliver`.
   - Guard `maxFrameSize > 0` in `CryptoFrameDeliverer.chunk`.
   - Validate `space` range in `SentPacketTracker.onAck`.

3. **Medium-term (LOW)**
   - Add non-negative checks to `PacketNumberSpaceManager`, `LossDetector`.
   - Add rate limiting to `HandshakeStateMachine`.
   - Add `maxFramesPerPacket` to `PacketReceiver`.
   - Harden `HeaderProtection._readVarInt` or replace with shared `VarInt.decode`.
   - Document backpressure requirements for `UdpSocket` consumers.

---

## Conclusion

The dart_quic project has made significant defensive improvements since V1. Core QUIC recovery, flow-control, and state-machine components now have appropriate caps and validations. However, the **CRYPTO stream assembler was overlooked** and remains an unbounded growth vector. Additionally, several parsing utilities (`CoalescedPacket`, `HeaderProtection`) contain custom varint decoders that lack the bounds checking present in the shared `VarInt` class, creating crash-on-malformed-input vulnerabilities. Fixing these remaining gaps will bring the codebase to a robust defensive posture.

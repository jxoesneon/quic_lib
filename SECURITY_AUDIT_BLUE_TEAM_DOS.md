# BLUE TEAM DoS / Connection Hardening Security Audit

**Project:** dart_quic  
**Auditor:** Defensive Security Engineer (Blue Team)  
**Date:** 2025-01-18  
**Scope:** Connection management, recovery mechanisms, stream handling, and anti-amplification controls.  
**Files Audited:** 16 source files under `lib/src/`

---

## Executive Summary

This audit identified **21 security findings** across the audited files. The most critical issues are:

1. **Unbounded memory growth** in `ReassemblyBuffer`, `ConnectionRegistry`, `MigrationHelper._pendingChallenges`, `LossDetector._sentTimes`, and `SentPacketTracker._spaces`. An attacker can exhaust server memory by sending crafted packets without any throttling.
2. **Flow controller unbounded window growth** — `FlowController.shouldUpdateWindow()` doubles the window indefinitely with no maximum cap.
3. **Simplified ACK parsing vulnerability** in `SentPacketTracker` — an attacker can falsely acknowledge all in-flight packets with a single large `largestAcked` value.
4. **Missing packet number replay protection** — `PacketNumberSpaceManager.onReceived()` only tracks `largestReceived` but does not reject old/replayed packet numbers.
5. **Connection registry unbounded growth** — no maximum number of registered connections or CID length validation.
6. **Rate limiting absent** across all subsystems — no throttling on state transitions, stream allocation, challenge generation, or packet tracking.

---

## Detailed Findings

### 1. Missing Limits

#### 1.1 Connection Registry — No Max Connection Limit
**File:** `lib/src/connection/connection_registry.dart` (lines 5, 10-12)  
**Severity:** HIGH  
**Description:** `ConnectionRegistry._registry` is an unbounded `Map<String, Object>`. There is no maximum size limit, no CID length validation, and no eviction policy. An attacker can register arbitrarily many short CIDs and exhaust memory.  
**Impact:** Memory exhaustion DoS.  
**Recommendation:** Add `maxConnections` constant; validate CID length (min 8, max 20 per RFC 9000); reject registrations when at capacity.

#### 1.2 Migration Helper — No Max Pending Challenges / Validated Paths
**File:** `lib/src/connection/migration_helper.dart` (lines 11, 14, 23-28)  
**Severity:** HIGH  
**Description:** `_pendingChallenges` and `_validatedPaths` have no size limits. `generateChallenge()` can be called indefinitely. Each challenge is 8 bytes + overhead.  
**Impact:** Memory exhaustion DoS via PATH_CHALLENGE flooding.  
**Recommendation:** Add `maxPendingChallenges` (e.g., 8) and `maxValidatedPaths` (e.g., 16). Evict oldest on overflow.

#### 1.3 Loss Detector — Unbounded Sent-Time Tracking
**File:** `lib/src/recovery/loss_detector.dart` (lines 16, 19-22)  
**Severity:** HIGH  
**Description:** `_sentTimes` Map tracks every sent packet until it is ACKed or declared lost. If an attacker never ACKs packets, the map grows without bound.  
**Impact:** Memory exhaustion DoS.  
**Recommendation:** Add a max tracked packets limit and age out old entries.

#### 1.4 Sent Packet Tracker — Unbounded Packet Storage
**File:** `lib/src/recovery/sent_packet_tracker.dart` (lines 24, 27-29)  
**Severity:** HIGH  
**Description:** `_spaces` stores `SentPacketInfo` for every sent packet per space. Simplified ACK logic (lines 38-45) removes entries only when `packetNumber <= largestAcked`, but if ACKs are never sent, memory grows indefinitely.  
**Impact:** Memory exhaustion DoS.  
**Recommendation:** Add max in-flight packets per space and periodic cleanup.

#### 1.5 Reassembly Buffer — No Size / Offset Limit
**File:** `lib/src/streams/reassembly_buffer.dart` (lines 5, 10-13)  
**Severity:** CRITICAL  
**Description:** `insert()` accepts any offset and any data size with no validation, no deduplication, and no maximum buffer size. An attacker can send 1-byte chunks at widely spaced offsets (e.g., offset 0, 1 GiB, 2 GiB, …) causing `_buffer` to contain enormous sparse keys while consuming minimal ingress bandwidth.  
**Impact:** Severe memory exhaustion DoS.  
**Recommendation:** Enforce `maxBufferSize`, `maxOffsetGap`, and `maxFragmentCount` limits. Reject inserts that would exceed limits.

#### 1.6 Flow Controller — Unbounded Window Growth
**File:** `lib/src/streams/flow_controller.dart` (lines 33-39)  
**Severity:** MEDIUM  
**Description:** `shouldUpdateWindow()` doubles `_advertisedLimit` indefinitely (`_nextLimit = _advertisedLimit * 2`). There is no maximum cap.  
**Impact:** Peer can drive window to astronomical values, leading to integer bloat and potential downstream memory pressure if peer tries to send that much.  
**Recommendation:** Cap `_maxData` and `_nextLimit` to a reasonable upper bound (e.g., 16 MB per stream, 256 MB per connection).

#### 1.7 Connection ID Manager — Unbounded Retired CID Storage
**File:** `lib/src/connection/connection_id_manager.dart` (lines 29, 84-88)  
**Severity:** MEDIUM  
**Description:** `_retired` CIDs are never removed. An attacker who can force frequent retirements (via `retirePriorTo`) will cause `_retired` to grow without bound.  
**Impact:** Slow memory exhaustion.  
**Recommendation:** Limit retired CID history to the most recent N entries (e.g., 32).

#### 1.8 Stream ID Allocator — No Per-Connection Stream Limit
**File:** `lib/src/streams/stream_id.dart` (lines 71-123)  
**Severity:** MEDIUM  
**Description:** While `maxStreamId` is enforced globally (`2^62 - 1`), there is no per-connection or per-category limit on how many streams can be allocated in a short time.  
**Impact:** Rapid stream allocation can exhaust connection memory and CPU.  
**Recommendation:** Add per-category rate limits and a per-connection active-stream cap.

#### 1.9 Congestion Controller — No Max CWND Cap
**File:** `lib/src/recovery/congestion_controller.dart` (lines 13, 51-57)  
**Severity:** LOW  
**Description:** `_congestionWindow` can grow without an upper bound during sustained ACKs.  
**Impact:** Unbounded memory commitment for in-flight data.  
**Recommendation:** Cap `congestionWindow` to a max value (e.g., 256 MB).

#### 1.10 PTO Scheduler — Unbounded Backoff Counter
**File:** `lib/src/recovery/pto_scheduler.dart` (lines 9, 37-39)  
**Severity:** LOW  
**Description:** `_ptoCount` increments without limit on every PTO fire. In Dart this won't overflow, but the PTO duration becomes effectively infinite, making recovery impossible.  
**Impact:** Connection hang / self-DoS after many PTOs.  
**Recommendation:** Cap `_ptoCount` (e.g., max 10) and close the connection after max PTOs exceeded.

---

### 2. Rate Limiting Gaps

#### 2.1 Global Absence of Rate Limiting
**Files:** All audited files  
**Severity:** HIGH  
**Description:** No subsystem implements rate limiting, token buckets, or call-frequency throttling. An attacker can flood: state transitions, stream opens, CIDs, PATH_CHALLENGES, packet tracking entries, and reassembly inserts.  
**Impact:** CPU exhaustion and memory exhaustion even without exploiting specific unbounded structures.  
**Recommendation:** Introduce a central `RateLimiter` utility and apply it to all public mutation APIs.

#### 2.2 Connection State Machine — No Transition Flood Protection
**File:** `lib/src/connection/connection_state_machine.dart` (lines 55-78)  
**Severity:** MEDIUM  
**Description:** `transitionTo()` can be called in a tight loop. Invalid transitions throw, but valid ones (e.g., idle → handshaking → closed loop if recreated) do not.  
**Impact:** CPU exhaustion via rapid valid transitions.  
**Recommendation:** Add a per-connection transition rate limit.

---

### 3. State Machine Bypasses

#### 3.1 Connection State Machine — Missing "Any → Closed" for closing/draining in docs vs code
**File:** `lib/src/connection/connection_state_machine.dart` (lines 85-102)  
**Severity:** LOW  
**Description:** The class documentation states "Any → closed (on immediate abort)", but `_isValidTransition` already permits `established → closed`, `handshaking → closed`, `idle → closed`, `closing → closed`, and `draining → closed`. In practice the code is **more restrictive** than the docs (which is safe). However, `closing → closed` and `draining → closed` are allowed, satisfying most abort paths. There is no actual bypass here, but the documentation/implementation mismatch could confuse callers.  
**Impact:** LOW — no exploitable bypass found.  
**Note:** Calling `abort()` from `closing` or `draining` IS allowed by the code, so the docs are accurate. The real concern is that once in `closed`, the machine does not prevent further `transitionTo(closed)` calls because `_isValidTransition(closed, closed)` returns `false`, but `transitionTo` checks `_state == newState` first and returns early. So repeated `abort()` calls on a closed state are no-ops, which is fine.

#### 3.2 Receive State Machine — Final Size Bypass via Data Injection
**File:** `lib/src/streams/receive_state_machine.dart` (lines 32-42, 74-78)  
**Severity:** MEDIUM  
**Description:** `onDataReceived()` does not validate the consistency of `offset` or `finalSize` against previously received data. An attacker could set a small `finalSize`, then send data beyond it in subsequent frames (though the caller would need to not enforce this). More critically, `_setFinalSize` only prevents *changing* the final size, but `onDataReceived` with `fin=true` silently transitions to `sizeKnown` without ensuring all data up to `finalSize` has actually arrived.  
**Impact:** Stream state confusion; potential for premature read completion.  
**Recommendation:** Validate data offsets against `finalSize` and reject data past the declared final size.

---

### 4. Amplification Limits

#### 4.1 Anti-Amplification Limit — Missing Integration & Edge Cases
**File:** `lib/src/security/anti_amplification_limit.dart` (lines 5-60)  
**Severity:** MEDIUM  
**Description:** The `AntiAmplificationLimit` class correctly implements the RFC 9000 §8 3× limit for bytes sent vs bytes received. However:
1. `canSend` returns `true` for `bytes <= 0` (line 40), allowing zero-length / negative sends when budget is exhausted. Negative sends could be exploited to game accounting if callers subtract instead of add.
2. There is no rate limiting on `onBytesReceived`.
3. The class is not visibly wired into `QuicConnection` or the packet sender.
4. No maximum `_bytesReceived` cap; arbitrary-precision integers prevent overflow, but an attacker can drive the value arbitrarily high.
**Impact:** If not wired into the send path, amplification attacks are possible. Zero/negative edge case is minor.  
**Recommendation:** Wire `AntiAmplificationLimit` into `QuicConnection` and packet builder; reject negative byte counts; add per-peer receive-rate limit.

---

### 5. Memory Exhaustion

This section consolidates the unbounded-growth findings already listed in Section 1. The highest-risk vectors are:

| Vector | File | Mechanism |
|--------|------|-----------|
| Sparse reassembly buffer | `reassembly_buffer.dart` | 1-byte chunks at huge offsets |
| Pending path challenges | `migration_helper.dart` | Unlimited `generateChallenge()` calls |
| Unacked sent packets | `loss_detector.dart` | Never-ACK flood |
| Unacked sent packets (tracker) | `sent_packet_tracker.dart` | Never-ACK flood |
| Retired CIDs | `connection_id_manager.dart` | Forced retirePriorTo flood |
| Connection registry | `connection_registry.dart` | Arbitrary CID registration |
| Flow window doubling | `flow_controller.dart` | Unbounded `MAX_DATA` updates |

---

### 6. Connection Hijacking

#### 6.1 Connection Registry — Weak CID Validation
**File:** `lib/src/connection/connection_registry.dart` (lines 10-12, 17-19)  
**Severity:** MEDIUM  
**Description:** The registry accepts any `List<int>` as a CID with no length validation. An attacker can register a 1-byte CID, increasing collision probability. Lookup is via simple hex encoding with no cryptographic binding.  
**Impact:** CID collision could cause misrouting; short CIDs are guessable.  
**Recommendation:** Enforce CID min length (8 bytes) and max length (20 bytes) per RFC 9000. Use `ConnectionIdManager` for generation.

#### 6.2 Connection ID Manager — Predictable Length Distribution
**File:** `lib/src/connection/connection_id_manager.dart` (lines 117-118)  
**Severity:** LOW  
**Description:** CID length is chosen uniformly from `minConnectionIdLength` to `maxConnectionIdLength`. While the bytes themselves are secure-random, the length is not secret and could slightly aid traffic analysis.  
**Impact:** Minimal — this is a defense-in-depth note, not an immediate vulnerability.  
**Recommendation:** Consider using a fixed CID length in high-security deployments.

---

### 7. Replay Protection

#### 7.1 Packet Number Space Manager — No Replay Rejection
**File:** `lib/src/recovery/packet_number_space.dart` (lines 60-67)  
**Severity:** HIGH  
**Description:** `onReceived()` only updates `largestReceived` if the new packet number is larger. It does **not** track previously received packet numbers and therefore cannot detect or reject replayed packets with numbers lower than `largestReceived`.  
**Impact:** An attacker can replay old packets, causing duplicate frame processing, duplicate stream data insertion, or spurious ACKs.  
**Recommendation:** Maintain a sliding window bitmap or a set of recently received packet numbers per space and reject duplicates.

#### 7.2 Sent Packet Tracker — Simplified ACK Parsing Allows False ACKs
**File:** `lib/src/recovery/sent_packet_tracker.dart` (lines 32-51)  
**Severity:** HIGH  
**Description:** `onAck()` acks **everything** `<= largestAcked` regardless of whether those packets were actually sent or whether the ACK ranges legitimately cover them. A single ACK frame with a huge `largestAcked` will clear the entire space.  
**Impact:** An attacker can falsely acknowledge all packets, bypassing loss detection and causing the sender to never retransmit.  
**Recommendation:** Implement proper ACK range parsing. Validate that `largestAcked` does not exceed the highest sent packet number. Track individual ACK ranges.

---

## Hardening Test Plan

Tests have been implemented in `test/security/hardening_test.dart` covering:

1. **Connection ID Manager** — verify `maxActiveIds` is enforced and retired CID history can grow (documented behavior test).
2. **Connection Registry** — verify unbounded registration is possible (to document the gap) and propose limits.
3. **Migration Helper** — verify challenge generation works but document no max limit.
4. **Reassembly Buffer** — verify unbounded insertion at large offsets (documented gap).
5. **Flow Controller** — verify unbounded window doubling (documented gap).
6. **Loss Detector** — verify sent-times tracking without ACKs.
7. **Sent Packet Tracker** — verify simplified ACK parsing vulnerability (false ACK of unsent packets).
8. **Anti-Amplification** — verify 3× limit, zero-byte edge case, and address validation bypass.
9. **State Machine** — verify valid transitions are enforced and invalid ones throw.
10. **Packet Number Replay** — verify `PacketNumberSpaceManager` does not reject old packet numbers.
11. **Rate Limiting** — verify that rapid API calls are not throttled (to document the gap).

---

## Recommendations Summary

| Priority | Action |
|----------|--------|
| P0 | Cap `ReassemblyBuffer` fragment count, offset gap, and total buffered bytes. |
| P0 | Implement proper ACK range parsing in `SentPacketTracker` and validate `largestAcked` against highest sent PN. |
| P0 | Add replay-protection window to `PacketNumberSpaceManager`. |
| P1 | Add `maxPendingChallenges`, `maxValidatedPaths` to `MigrationHelper`. |
| P1 | Add `maxConnections` and CID length validation to `ConnectionRegistry`. |
| P1 | Add max tracked packets and periodic cleanup to `LossDetector` and `SentPacketTracker`. |
| P1 | Cap retired CID history in `ConnectionIdManager`. |
| P1 | Add `maxWindowSize` to `FlowController`. |
| P2 | Introduce a centralized `RateLimiter` and apply to all public mutation APIs. |
| P2 | Wire `AntiAmplificationLimit` into `QuicConnection` send path. |
| P2 | Add per-connection stream allocation rate limit. |
| P2 | Cap `ptoCount` in `PtoScheduler` and close connection on excessive PTOs. |
| P3 | Validate RTT and ack-delay inputs in `RttEstimator`. |

---

*End of Audit Report*

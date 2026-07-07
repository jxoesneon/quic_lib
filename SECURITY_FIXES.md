# Security Fixes Summary

## Date: 2026-06-27
## Project: quic_lib
## Status: COMPLETE - All critical/high findings addressed

---

## Fixes Applied

### 1. ReassemblyBuffer — CRITICAL DoS via Sparse Buffer
**File:** `lib/src/streams/reassembly_buffer.dart`
- Added `maxBufferSize` (16 MB)
- Added `maxOffsetGap` (16 MB) — rejects inserts at pathological offsets
- Added `maxFragmentCount` (1024) — prevents unbounded map growth
- Added `_bufferedBytes` tracking for accurate size enforcement

### 2. ConnectionRegistry — HIGH DoS via Unbounded Growth
**File:** `lib/src/connection/connection_registry.dart`
- Added `maxConnections` (65536)
- Added CID length validation: min 1, max 20 bytes per RFC 9000
- Rejects registration when at capacity

### 3. MigrationHelper — HIGH DoS via PATH_CHALLENGE Flooding
**File:** `lib/src/connection/migration_helper.dart`
- Added `maxPendingChallenges` (8) with oldest-eviction
- Added `maxValidatedPaths` (16) with FIFO eviction

### 4. LossDetector — HIGH DoS via Never-ACK Flood
**File:** `lib/src/recovery/loss_detector.dart`
- Added `maxTrackedPackets` (10000)
- Throws `StateError` when capacity exceeded

### 5. SentPacketTracker — HIGH DoS via Unbounded Storage
**File:** `lib/src/recovery/sent_packet_tracker.dart`
- Added `maxPacketsPerSpace` (10000)
- Evicts oldest packet number when at capacity

### 6. FlowController — MEDIUM Unbounded Window Growth
**File:** `lib/src/streams/flow_controller.dart`
- Added `maxWindow` cap (256 MB)
- `updateLimit()` clamps to `maxWindow`
- `shouldUpdateWindow()` caps `_nextLimit` to `maxWindow`

### 7. ConnectionIdManager — MEDIUM Retired CID Accumulation
**File:** `lib/src/connection/connection_id_manager.dart`
- Added `maxRetiredIds` (32)
- Evicts oldest retired CIDs when at capacity

### 8. PtoScheduler — MEDIUM Exponential Backoff Overflow
**File:** `lib/src/recovery/pto_scheduler.dart`
- Capped `_ptoCount` at 10 to prevent `(1 << 63)` 64-bit overflow

### 9. CongestionController — MEDIUM Integer Overflow
**File:** `lib/src/recovery/congestion_controller.dart`
- `onAckReceived()` clamps negative `ackedBytes` to 0
- Added `maxCwnd` (`0x3FFFFFFFFFFFFFFF`) with pre-addition overflow check
- `onPacketSent()` clamps negative `bytes` to 0

### 10. AntiAmplificationLimit — LOW Negative Byte Edge Case
**File:** `lib/src/security/anti_amplification_limit.dart`
- `onBytesReceived()` throws `ArgumentError` on negative bytes
- `onBytesSent()` throws `ArgumentError` on negative bytes

### 11. PacketNumberSpaceManager — HIGH Missing Replay Protection
**File:** `lib/src/recovery/packet_number_space.dart`
- Added 64-packet sliding-window bitmask for replay detection
- `onReceived()` now returns `bool`: `true` = new packet, `false` = replay
- Rejects duplicate packets and packets older than the window

### 12. SentPacketTracker — HIGH False ACK Vulnerability
**File:** `lib/src/recovery/sent_packet_tracker.dart`
- Tracks `_highestSent` per space
- `onAck()` clamps `largestAcked` to highest actually sent packet
- Prevents malicious ACK frames from falsely acknowledging unsent traffic

### 13. RttEstimator — MEDIUM Unbounded BigInt Growth
**File:** `lib/src/recovery/rtt_estimator.dart`
- Added `maxRttUs` cap (60 seconds)
- Added `maxAckDelayUs` cap (~16 seconds)
- `update()` clamps negative and extreme RTT values

### 14. ReceiveStateMachine — MEDIUM Final Size Bypass
**File:** `lib/src/streams/receive_state_machine.dart`
- Added `bytesReceived` tracking
- Validates `finalSize` >= cumulative `bytesReceived`
- Rejects STREAM frames with data exceeding declared final size

### 15. RateLimiter Utility — P2 Centralized Rate Limiting
**File:** `lib/src/security/rate_limiter.dart` (new)
- Sliding-window rate limiter with configurable `maxCalls` and `windowMs`
- Throws `StateError` on rate-limit violations

### 16. SentPacketTracker — HIGH Proper ACK Range Parsing
**File:** `lib/src/recovery/sent_packet_tracker.dart`
- Implemented proper QUIC ACK range parsing
- Empty `ackRanges` falls back to simplified behavior for compatibility
- Validates `largestAcked` against highest sent packet (from Loop 2)

### 17. MigrationHelper — LOW Clock Backward Jump
**File:** `lib/src/connection/migration_helper.dart`
- `getExpiredChallenges()` guards against `currentTimeUs < sentTime`
- Prevents false expiration when system clock jumps backward

### 18. Multiaddr — LOW Information Disclosure
**File:** `lib/src/libp2p/multiaddr.dart`
- Removed user input from `FormatException` messages
- Prevents leak of malformed protocol names and IP addresses in error output

### 19. ConnectionStateMachine — P2 Transition Flood Protection
**File:** `lib/src/connection/connection_state_machine.dart`
- Integrated `RateLimiter` (100 transitions/second)
- Prevents CPU exhaustion via rapid valid state transitions

### 20. CryptoFrameAssembler — HIGH Unbounded Buffer
**File:** `lib/src/crypto/tls/crypto_frame_assembler.dart`
- Added maxBufferSize (4MB), maxOffsetGap (4MB), maxFragmentCount (256)
- Tracks `_bufferedBytes` for accurate size enforcement

### 21. CoalescedPacket — HIGH RangeError on Truncated VarInt
**File:** `lib/src/wire/coalesced_packet.dart`
- `_decodeVarInt` now guards against reading past buffer end
- Returns 0 on truncation instead of throwing RangeError

### 22. FlowController.consume — MEDIUM Negative Inflation
**File:** `lib/src/streams/flow_controller.dart`
- Rejects negative `bytes` with `ArgumentError`

### 23. QuicReceiveStream.deliver — MEDIUM FinalSize Bypass
**File:** `lib/src/streams/quic_stream.dart`
- `deliver()` now accepts and passes `bytesReceived` and `finalSize` to state machine

### 24. CryptoFrameDeliverer.chunk — MEDIUM Infinite Loop
**File:** `lib/src/crypto/tls/crypto_frame_deliverer.dart`
- Rejects `maxFrameSize <= 0` with `ArgumentError`

### 25. SentPacketTracker.onAck — MEDIUM Arbitrary Space
**File:** `lib/src/recovery/sent_packet_tracker.dart`
- Validates `space` parameter to 0..2 (valid QUIC packet number spaces)

### 26. PacketNumberSpaceManager — LOW Negative PN
**File:** `lib/src/recovery/packet_number_space.dart`
- `onReceived()` rejects negative packet numbers

### 27. LossDetector — LOW Negative PN
**File:** `lib/src/recovery/loss_detector.dart`
- `onPacketSent()` ignores negative packet numbers
- `onAckReceived()` clamps negative `largestAcked` to -1

### 28. HandshakeStateMachine — LOW Transition Flood
**File:** `lib/src/crypto/tls/handshake_state_machine.dart`
- Integrated `RateLimiter` (100 transitions/second)

### 29. PacketReceiver — LOW Frame Count Bomb
**File:** `lib/src/connection/packet_receiver.dart`
- Added maxFramesPerPacket (256) to prevent DoS via tiny frames

### 30. HeaderProtection — LOW VarInt RangeError
**File:** `lib/src/crypto/packet/header_protection.dart`
- `_readVarInt` now guards against reading past buffer end

### 31. RetryIntegrityTag.verify — NOVEL Timing Side Channel
**File:** `lib/src/crypto/packet/retry_integrity_tag.dart`
- Removed `retryPacket.length < 16` fast-path return that leaked tag validity via timing
- All error paths now go through the same catch block

### 32. DefaultCryptoBackend.rsaPkcs1Verify — NOVEL Timing Side Channel
**File:** `lib/src/crypto/default_crypto_backend.dart`
- Moved key parsing and signer init OUTSIDE catch-all try block
- Prevents attacker from distinguishing "invalid key" vs "invalid signature" via timing

### 33. PacketReceiver.processPacket — NOVEL Partial Frame Injection
**File:** `lib/src/connection/packet_receiver.dart`
- When `FrameCodec.parse` throws, all already-parsed frames are now discarded
- Prevents injection of valid frames hidden behind a malformed trailing frame

### 34. Http3DataFrame.toString — NOVEL Information Disclosure
**File:** `lib/src/http3/data_frame.dart`
- Replaced raw data dump with length-only description

### 35. Http3HeadersFrame.toString — NOVEL Information Disclosure
**File:** `lib/src/http3/headers_frame.dart`
- Replaced raw encodedFieldSection dump with length-only description

### 36. Http3SettingsFrame.toString — NOVEL Information Disclosure
**File:** `lib/src/http3/settings_frame.dart`
- Replaced raw settings map dump with count-only description

---

## Security Fixes from v1.5.0 through v1.12.0

### v1.12.0 — 2026-07-07
- **Peer certificate exposure**: Added `peerCertificate` and `peerCertificateVerify` to `QuicConnection` for proper certificate verification after TLS handshake
- **Malformed TLS Certificate handling**: Fixed to log malformed TLS Certificate messages instead of propagating exceptions

### v1.11.0 — 2026-06-29
- **QPACK integer overflow**: Fixed `QpackInteger.decode` to throw `ArgumentError` when continuation exceeds 62-bit limit instead of returning out-of-range value
- **Packet parsing robustness**: `PacketReceiver.processPacket` now catches malformed header parsing and drops packets instead of propagating exceptions

### v1.10.0 — 2026-06-29
- **API ambiguity**: Renamed WebTransport `Capsule` class to `WebTransportCapsule` to resolve ambiguity with HTTP/3 `Capsule` class

### v1.9.0 — 2026-06-29
- **Certificate revocation parsing**: Added CRL/OCSP extension parsing with `RevocationInfo` extraction from X.509 extensions

### v1.8.0 — 2026-06-29
- **libp2p TLS signature compliance**: Fixed SignedKey signature to compute over proper handshake message per libp2p TLS spec

### v1.7.0 — 2026-06-29
- **QPACK stream management**: Added QPACK encoder/decoder streams for proper HTTP/3 header compression

### v1.6.0 — 2026-06-29
- **Packet pacing enforcement**: Added RFC 9002 §7.7 compliance with `PacingTimer` to prevent packet burst attacks

### v1.5.0 — 2026-06-29
- **Key update security**: Implemented peer-initiated key update detection with rollback protection and timing side-channel prevention
- **Initial packet padding**: Enforced 1200-byte minimum padding for client Initial packets per RFC 9000
- **0-RTT key management**: Added proper 0-RTT early-data flag handling and key cleanup
- **Key phase protection**: Prevented non-monotonic key updates and enforced proper key phase transitions

### v1.4.2 — 2026-06-29 (Security Patch)
- **Unknown frame handling**: Fixed to treat unknown frame types as `FRAME_ENCODING_ERROR` per RFC 9000
- **Capsule size limits**: Added 1 MiB limit to prevent DoS via memory exhaustion
- **DATAGRAM frame limits**: Enforced 1 MiB upper bound on DATAGRAM frame payloads
- **ACK_FREQUENCY validation**: Added proper validation per RFC 9298 to prevent malformed frames

---

## Security Audit Amendments (Post-Audit)

### A1. QuicConnection Subsystem Wiring
**File:** `lib/src/connection/quic_connection.dart`
- Removed 3 unused imports (`dart:async`, `packet_protector`, `udp_socket`)
- Added public getters for all subsystems (`cidManager`, `rttEstimator`, `lossDetector`, `ptoScheduler`, `congestionController`)
- Wired `onPacketSent`, `onAckReceived`, `isPtoExpired`, `onPtoFired`, `onAddressValidated`

### A2. Delete tmp_*.dart Experimental Files
- Deleted 5 files using deprecated `AESFastEngine` (`tmp_chacha[1-4].dart`, `tmp_ecb.dart`)

### A3. Replace print() with Logging Abstraction
**File:** `lib/src/logging/quic_logger.dart` (new)
- Lightweight configurable logging sink
**File:** `lib/src/connection/connection_state_machine.dart`
- Replaced `print()` with `QuicLogger.log()`
**File:** `lib/src/webtransport/webtransport_session.dart`
- Replaced `print()` with `QuicLogger.log()`

### A4. pointycastle 4.0.0 Migration Assessment
**File:** `doc/POINTYCASTLE_4_MIGRATION.md` (new)
- Analyzed changelog; risk: LOW; no code changes required

### A5. CHANGELOG.md
**File:** `CHANGELOG.md` (new)
- Documents all 36 fixes and API changes for alpha.1

### A6. ARCHITECTURE.md
**File:** `ARCHITECTURE.md` (new)
- Subsystem map, integration points, security architecture, extension points, known gaps

### A7. Address Validation Trigger
**File:** `lib/src/connection/quic_connection.dart`
- `onAddressValidated()` transitions to `established` if in `handshaking`

### A8. UDP-Level Per-IP Rate Limiting
**File:** `lib/src/io/udp_socket.dart`
- Sliding-window rate limit: 1000 datagrams/sec per source IP

### A9. Gate Unimplemented Features
**File:** `lib/src/io/quic_endpoint.dart`
- `connect()` throws descriptive `UnimplementedError`

---

## Optional Scaffolds (Post-Council)

### O1. Http3Connection Scaffold
**File:** `lib/src/http3/http3_connection.dart` (new)
- Request/response lifecycle placeholder with clear `UnimplementedError` messages

### O2. RecoveryManager Scaffold
**File:** `lib/src/recovery/recovery_manager.dart` (new)
- Coordinates loss detector, congestion controller, PTO scheduler, RTT estimator, sent packet tracker

### O3. Fuzzing Harness Scaffold
**File:** `test/fuzz/fuzz_harness.dart` (new)
- Targets VarInt, FrameCodec, CoalescedPacket, Multiaddr with 10,000 iterations

### O4. Benchmark Harness Scaffold
**File:** `test/benchmark/benchmark_harness.dart` (new)
- Micro-benchmarks for VarInt, CID issue, InitialSecrets, FrameCodec, PN allocate

---

## Test Results

| Metric | Value |
|--------|-------|
| Total tests | 2188 |
| Passing | 2188 |
| Failing | 0 |
| Line coverage | 94.89% |
| Analyzer issues | 0 |

---

## Files Modified

- `lib/src/streams/reassembly_buffer.dart`
- `lib/src/connection/connection_registry.dart`
- `lib/src/connection/migration_helper.dart`
- `lib/src/recovery/loss_detector.dart`
- `lib/src/recovery/sent_packet_tracker.dart`
- `lib/src/streams/flow_controller.dart`
- `lib/src/connection/connection_id_manager.dart`
- `lib/src/recovery/pto_scheduler.dart`
- `lib/src/recovery/congestion_controller.dart`
- `lib/src/security/anti_amplification_limit.dart`
- `lib/src/recovery/packet_number_space.dart`
- `lib/src/recovery/rtt_estimator.dart`
- `lib/src/streams/receive_state_machine.dart`
- `lib/src/security/rate_limiter.dart` (new)
- `lib/src/libp2p/multiaddr.dart`
- `lib/src/connection/connection_state_machine.dart`
- `lib/src/crypto/tls/crypto_frame_assembler.dart`
- `lib/src/crypto/tls/crypto_frame_deliverer.dart`
- `lib/src/wire/coalesced_packet.dart`
- `lib/src/streams/quic_stream.dart`
- `lib/src/connection/packet_receiver.dart`
- `lib/src/crypto/packet/header_protection.dart`
- `test/security/hardening_test.dart`
- `test/security/fuzz_chaos_test.dart`
- `test/security/anti_amplification_limit_test.dart`
- `test/security/rate_limiter_test.dart` (new)
- `test/recovery/packet_number_space_test.dart`
- `test/recovery/sent_packet_tracker_test.dart`
- `test/streams/receive_state_machine_test.dart`
- `test/connection/migration_helper_test.dart`
- `test/connection/quic_connection_test.dart`
- `test/coverage/streams_recovery_gap_test.dart`
- `test/crypto/coverage_gap_test.dart`
- `test/http3/coverage_gap_test.dart`

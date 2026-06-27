# Changelog

All notable changes to `dart_quic` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-alpha.1] — 2026-06-27

### Security
- **36 security fixes** applied across 7 audit loops covering DoS, overflow, replay, info disclosure, timing side channels, and partial frame injection
- Added memory caps on all unbounded collections (ReassemblyBuffer, ConnectionRegistry, MigrationHelper, LossDetector, SentPacketTracker, FlowController, ConnectionIdManager, CryptoFrameAssembler)
- Added integer overflow protection (CongestionController cwnd cap, PtoScheduler ptoCount cap)
- Implemented 64-packet replay window in PacketNumberSpaceManager
- Added ACK validation and clamping in SentPacketTracker
- Added RTT clamping (60s max) and maxAckDelay cap (~16s)
- Added RateLimiter utility for state transition flood protection
- Added anti-amplification limit integration into QuicConnection
- Fixed timing side channels in RetryIntegrityTag.verify and DefaultCryptoBackend.rsaPkcs1Verify
- Fixed partial frame injection vulnerability in PacketReceiver
- Sanitized toString() methods in HTTP/3 frame types to prevent info disclosure via logging

### Added
- `RateLimiter` utility class for sliding-window rate limiting
- `AntiAmplificationLimit` tracker per RFC 9000 Section 8
- `QuicLogger` lightweight logging abstraction (replaces stdout print calls)
- Per-source IP UDP rate limiting in `UdpSocket` (1000 datagrams/sec)
- Integration wiring in `QuicConnection`: `onPacketSent`, `onAckReceived`, `isPtoExpired`, `onPtoFired`, `onAddressValidated`
- Public getters for all `QuicConnection` subsystems (`cidManager`, `rttEstimator`, `lossDetector`, `ptoScheduler`, `congestionController`)

### Changed
- `ConnectionStateMachine` and `WebTransportSession` now use `QuicLogger` instead of `print()`
- `FlowController.consume()` now rejects negative byte counts
- `SentPacketTracker.onAck()` validates space parameter to 0..2
- `PacketNumberSpaceManager.onReceived()` rejects negative packet numbers
- `LossDetector` ignores negative packet numbers and clamps negative `largestAcked`
- `CryptoFrameDeliverer.chunk()` rejects non-positive `maxFrameSize`
- `CoalescedPacket._decodeVarInt()` and `HeaderProtection._readVarInt()` now guard against buffer over-read
- `PacketReceiver` discards all frames when any frame parse fails

### Removed
- 5 experimental `tmp_*.dart` crypto scratchpad files using deprecated `AESFastEngine`
- Unused imports and fields in `QuicConnection`

### Fixed
- Analyzer warnings: reduced from 10 to 0 in `lib/src/`

### Documentation
- Added 7 security audit reports (Blue Team V1/V2/V3, Red Team V1/V2/Novel, Meta-Analysis)
- Added `SECURITY_FIXES.md` tracking all 36 fixes
- Added `doc/POINTYCASTLE_4_MIGRATION.md`

---

## [0.1.0-alpha.1-pre] — 2026-06-25

### Added
- Initial alpha release with modular QUIC, HTTP/3, WebTransport, and libp2p components
- Wire format: VarInt, packet headers, frame types, coalesced packets
- Crypto: TLS 1.3 handshake scaffold, key derivation, header protection, packet protection
- Recovery: LossDetector, SentPacketTracker, CongestionController, RttEstimator, PtoScheduler
- Streams: StreamId, SendStateMachine, ReceiveStateMachine, ReassemblyBuffer, FlowController
- Connection: ConnectionStateMachine, ConnectionIdManager, ConnectionRegistry, MigrationHelper
- HTTP/3: All frame types, SETTINGS, QPACK static table encoder
- WebTransport: Session state machine, capsule types
- libp2p: Multiaddr parser, PeerId, DCUtR message scaffold
- 1000+ tests with 96%+ line coverage

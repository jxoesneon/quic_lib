# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete specification suite for QUIC, HTTP/3, and WebTransport.
- QPACK codec specification (RFC 9204).
- QUIC transport parameters specification (RFC 9000 Section 18).
- QUIC datagram extension specification (RFC 9221).
- CUBIC congestion control specification.
- DCUTR NAT traversal specification.
- Unified error code registry.
- RFC test vectors appendix.
- Fuzzing strategy and performance benchmarking specifications.
- Versioning and release policy.
- Security specification with STRIDE threat analysis and supply-chain security.
- Extension and contribution guide.
- dart_ipfs integration contract.
- Seven Architecture Decision Records (ADRs).
- GitHub Actions CI workflow template.

### Changed
- All 21 specifications graduated from `1.0-draft` to `1.0` (stable specification release).
- All cross-references verified and resolved (zero broken links).
- Dart API consolidated into `DART_API_SPEC.md` as the single authoritative source.
- Architecture Decision Records (ADRs) accepted and locked.

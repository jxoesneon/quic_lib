---
title: "Security Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Security Model & Threat Mitigation"
rfc_basis:
  - "RFC 9000 Section 21"
  - "RFC 9001 Section 9"
  - "RFC 8446"
dependencies:
  - "ROADMAP.md"
---

# Security Specification



## 1. Purpose

QUIC design eliminates many TCP/TLS attack vectors, but it also introduces new ones-amplification via Initial packets, migration linkability, and 0-RTT replay. Without an explicit security model, implementers will make inconsistent trust assumptions. This spec enumerates the threats and mandates the mitigations that keep dart_quic safe for P2P and server use.

## 2. Detailed Specification
### 2.1 Threat Model

#### 2.1.1 Attacker Capabilities

| Attacker Type | Capabilities | Threat Level |
|--------------|-------------|--------------|
| **Passive on-path** | Observe all packets; cannot modify or inject | Medium |
| **Active on-path** | Observe, modify, inject, drop packets | High |
| **Off-path** | Cannot observe traffic; can send spoofed packets | Low-Medium |
| **Compromised peer** | Controls one endpoint; may violate protocol | High |

#### 2.1.2 Assets to Protect

| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|--------------|
| Application data | Required | Required | Required |
| Handshake data | Partial (Initial visible) | Required | Required |
| Connection metadata | Best-effort | Required | Required |
| Peer identity | Required (for libp2p) | Required | Required |
| Session keys | Critical | Critical | Required |

---


### 2.2 TLS 1.3 Requirements

#### 2.2.1 Mandatory Cipher Suites

The implementation MUST support:
- `TLS_AES_128_GCM_SHA256` (mandatory per RFC 9001)

The implementation SHOULD support:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

#### 2.2.2 TLS Version

- MUST use TLS 1.3 or higher.
- MUST NOT negotiate TLS 1.2 or lower.
- MUST reject connections attempting downgrade.

#### 2.2.3 Key Exchange

- MUST support X25519.
- SHOULD support P-256 (secp256r1).
- MAY support X448, P-384, P-521.

#### 2.2.4 Signature Algorithms

- MUST support Ed25519, ECDSA with P-256.
- SHOULD support RSA-PSS (>= 2048 bits).

---


### 2.3 Certificate Handling

#### 2.3.1 Standard QUIC (non-libp2p)

- Server MUST present a valid certificate chain.
- Client MUST validate:
  - Certificate chain up to a trusted CA root.
  - Server name (SNI) matches certificate Subject Alternative Name.
  - Certificate is not expired or revoked.
  - Certificate public key meets minimum strength requirements.

#### 2.3.2 libp2p Mode

- Both peers present self-signed certificates (Section 4 of LIBP2P_QUIC_SPEC.md).
- Validation is against the libp2p Public Key Extension, not CA chains.
- Peer ID is the trust anchor.

#### 2.3.3 Certificate Storage

- Private keys MUST be held in memory only during the connection lifetime.
- No plaintext key material on disk.
- Dart `SecurityContext` handles key loading from PEM/DER files.

---


### 2.4 Amplification Protection (RFC 9000 Section 8)

#### 2.4.1 Server Anti-Amplification

Before address validation, the server MUST NOT send more than **3 times** the number of bytes received from the client:

```
max_bytes = 3 * bytes_received_from_client
```

#### 2.4.2 Address Validation Mechanisms

| Mechanism | When Used | How |
|-----------|-----------|-----|
| Retry token | On Initial packet | Server sends Retry; client proves it received it |
| PATH_RESPONSE | Connection migration | Peer proves it's at the new address |
| Handshake completion | After handshake | Client has been validated by completing TLS |
| NEW_TOKEN | Future connections | Server provides token for future use |

#### 2.4.3 Initial Packet Padding

Client's first Initial packet MUST be padded to at least **1200 bytes**:
```dart
if (isInitialPacket && totalSize < 1200) {
  addPaddingFrames(1200 - totalSize);
}
```

This ensures the client sends enough data for the server's 3x amplification limit to permit a full response.

---


### 2.5 Replay Protection

#### 2.5.1 0-RTT Replay

0-RTT data is inherently replayable because it is encrypted with keys derived from a previous session. Mitigations:

| Strategy | Implementation |
|----------|---------------|
| **Idempotent-only** | Only allow safe HTTP methods (GET, HEAD) in 0-RTT |
| **Single-use tickets** | Server invalidates session ticket after first use |
| **Time window** | Reject 0-RTT data older than a configured threshold |
| **Application awareness** | API clearly marks data as 0-RTT; app decides safety |

#### 2.5.2 Dart API Marking

```dart
class QuicStream {
  /// Whether this stream carries 0-RTT (potentially replayable) data.
  bool get isEarlyData;
}
```

---


### 2.6 Downgrade Protection

#### 2.6.1 Version Downgrade

- QUIC Version Negotiation uses integrity protection (RFC 8999).
- The `version` field in packet headers is authenticated by packet protection.
- An attacker cannot trick endpoints into using an older QUIC version.

#### 2.6.2 TLS Downgrade

- TLS 1.3's downgrade sentinel (in ServerHello.random) prevents TLS version downgrade.
- QUIC MUST NOT use TLS versions below 1.3.

#### 2.6.3 Cipher Suite Downgrade

- Client and server negotiate cipher suites via TLS 1.3's normal mechanism.
- The negotiated cipher suite is covered by the Finished MAC — tampering is detected.

---


### 2.7 Denial-of-Service Protection

#### 2.7.1 Connection-Level DoS

| Attack | Mitigation |
|--------|-----------|
| SYN flood (Initial flood) | Retry tokens; amortize per-connection state |
| Slowloris (slow handshake) | Handshake timeout; limit concurrent handshakes |
| Resource exhaustion | Limit max connections per IP; memory budgets |

#### 2.7.2 Stream-Level DoS

| Attack | Mitigation |
|--------|-----------|
| Stream flood | Enforce MAX_STREAMS; rate-limit stream creation |
| Data flood | Flow control limits (MAX_DATA, MAX_STREAM_DATA) |
| RESET_STREAM flood | Rate-limit resets; close connection on abuse |
| Header bomb | SETTINGS_MAX_FIELD_SECTION_SIZE |

#### 2.7.3 Implementation Limits

```dart
class SecurityLimits {
  static const int maxConnectionsPerIp = 100;
  static const int maxConcurrentHandshakes = 50;
  static const Duration handshakeTimeout = Duration(seconds: 10);
  static const int maxStreamResetRate = 100;  // per second
  static const int maxMemoryPerConnection = 4 * 1024 * 1024;  // 4 MB
}
```

---


### 2.8 Connection ID Security

#### 2.8.1 Linkability Prevention

- Endpoints use NEW_CONNECTION_ID to provide multiple CIDs.
- After migration, old CID is retired (RETIRE_CONNECTION_ID).
- On-path observers cannot link activity across network changes.

#### 2.8.2 Stateless Reset

- If an endpoint loses state, it can send a Stateless Reset.
- The reset token is derived from the CID using a static key known only to the endpoint.
- Prevents off-path attackers from forging resets.

```
reset_token = HMAC-SHA256(static_key, connection_id)[0..16]
```

---


### 2.9 Timing Side-Channels

#### 2.9.1 Constant-Time Operations

The following MUST be constant-time:
- AEAD tag comparison (authentication verification).
- HMAC comparison (for stateless reset tokens).
- Certificate signature verification result comparison.

#### 2.9.2 Timing Leak Prevention

- Do NOT branch on secret data.
- Use Dart's secure comparison utilities where available.
- Consider packet processing time uniformity (pad to fixed time if necessary for high-security deployments).

---


### 2.10 Randomness Requirements

| Usage | Source | Quality |
|-------|--------|---------|
| Connection IDs | `Random.secure()` | Cryptographically secure |
| PATH_CHALLENGE data | `Random.secure()` | Cryptographically secure |
| Retry token nonce | `Random.secure()` | Cryptographically secure |
| TLS key shares | Crypto library | Cryptographically secure |
| Packet number (initial) | `Random.secure()` | Unpredictable start |

NEVER use `Random()` (non-secure) for any security-relevant value.

---


### 2.11 Logging and Diagnostics

#### 2.11.1 Safe Logging

| Data | Log Level | Allowed? |
|------|-----------|----------|
| Connection IDs | Debug | Yes |
| Packet numbers | Trace | Yes |
| Frame types | Debug | Yes |
| Header values | — | **NO** (may contain auth tokens) |
| Key material | — | **NEVER** |
| Certificate data | Debug | Fingerprint only |
| Error messages | Info | Yes (sanitized) |

#### 2.11.2 Audit Trail

Log security-relevant events:
- Connection establishment (peer identity, cipher suite).
- Certificate validation failures.
- Authentication failures.
- Anomalous behavior (too many resets, address spoofing attempts).

---





### 2.12 STRIDE Threat Analysis

The following maps QUIC/HTTP3/WebTransport-specific threats to the STRIDE categories.

#### 2.12.1 Spoofing (S)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Peer identity spoofing | Attacker presents a forged certificate or libp2p Public Key Extension. | Certificate chain validation (§2.3.1); libp2p Peer ID verification (§2.3.2). |
| Connection migration hijacking | Off-path attacker sends PATH_CHALLENGE from a spoofed address. | PATH_RESPONSE validation; anti-amplification limit (§2.4). |
| Retry token forgery | Attacker crafts a valid retry token without server state. | Token includes server-chosen entropy and expires quickly. |

#### 2.12.2 Tampering (T)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| In-flight packet modification | Active on-path attacker flips bits in encrypted packets. | AEAD authentication rejects tampered packets (TLS 1.3 record layer). |
| Certificate injection | Attacker injects a rogue certificate during handshake. | Certificate pinning or CA-chain validation (§2.3.1). |
| Frame reordering | Attacker reorders STREAM frames to corrupt application data. | QUIC stream offsets guarantee in-order delivery; duplicate detection rejects replays. |

#### 2.12.3 Repudiation (R)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Missing audit trail | Operator cannot prove a connection event occurred. | Security event logging (§2.11.2); signed event streams for high-assurance deployments. |
| Denial of connection existence | Peer claims no connection was established. | TLS 1.3 Finished MAC binds the transcript; both sides hold cryptographic proof. |

#### 2.12.4 Information Disclosure (I)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Traffic analysis | Observer infers application behavior from packet timing/size. | Connection ID rotation (§2.8.1); padding; coalescing. |
| ACK timing side-channel | Observer deduces application data from ACK timing patterns. | ACK delay exponent and delayed ACK strategy (§2.9). |
| Certificate metadata exposure | SNI or certificate SAN reveals peer identity. | ECH (Encrypted Client Hello) when available; libp2p uses hashed Peer IDs. |

#### 2.12.5 Denial of Service (D)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Amplification attack | Attacker spoofs victim address in Initial packet. | Anti-amplification limit (§2.4); Retry token for address validation. |
| Resource exhaustion | Attacker opens many streams or sends giant frames. | MAX_STREAMS, MAX_DATA, MAX_STREAM_DATA limits (§2.7.2). |
| Handshake flooding | Attacker sends many Initial packets without completing handshake. | Retry tokens; handshake timeout; per-IP connection limits (§2.7.1). |
| Datagram abuse | Attacker sends oversized or rapid datagrams. | max_datagram_frame_size limit; datagram rate limiting. |

#### 2.12.6 Elevation of Privilege (E)

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Stream ID misuse | Attacker opens a server-initiated bidirectional stream. | Strict stream ID validation; peer-initiated vs. local-initiated checks. |
| Frame type confusion | Attacker sends a valid frame in an invalid context. | State-machine validation (e.g., no STREAM frames in handshake). |
| Unauthorized migration | Attacker forces connection migration to a new path. | PATH_CHALLENGE/PATH_RESPONSE required; new path must pass validation. |

---



### 2.13 Supply-Chain Security

1. **Dependency Vetting**: All dependencies must be pure-Dart and pinned in pubspec.lock. No binary blobs, no transitive native extensions without audit.
2. **SBOM Generation**: An SPDX JSON software bill of materials is generated for every stable release and attached to the GitHub Release.
3. **CVE Monitoring**: Dependabot or OSV-Scanner runs on every PR and weekly on main to detect known vulnerabilities in dependencies.
4. **Third-Party Audit**: An external security audit is required before 1.0.0 and annually thereafter for stable releases.
5. **Build Reproducibility**: CI builds use pinned Dart SDK versions. Docker images (if used) are built from locked source archives with checksum verification.
6. **Package Signing**: pub.dev releases are signed via the publisher account. SHA-256 checksums of the release archive are published in release notes.

---


## 3. Acceptance Criteria

- [ ] TLS 1.3 handshake completes with all mandatory cipher suites.
- [ ] TLS 1.2 and below are rejected.
- [ ] Certificate validation rejects expired, invalid, and mismatched certificates.
- [ ] Anti-amplification: server sends <= 3x bytes before validation.
- [ ] Initial packets are padded to >= 1200 bytes.
- [ ] 0-RTT data is clearly marked in the API.
- [ ] Stateless reset works correctly.
- [ ] Connection IDs are rotated on migration.
- [ ] MAX_STREAMS, MAX_DATA limits are enforced.
- [ ] `Random.secure()` is used for all security-critical randomness.
- [ ] No key material appears in logs at any level.
- [ ] Timing-safe comparison is used for all tag/token verification.

---


## 4. Dependencies

- TLS 1.3 engine (crypto subsystem).
- Wire codec (packet headers for protection).
- Connection manager (amplification limits, handshake timeouts).
- Dart `Random.secure()`.
- `package:cryptography` for HMAC, AEAD.

---




## Used By

- [ROADMAP.md](ROADMAP.md) — Lists SECURITY_SPEC as a formal specification deliverable.
## 5. Testing Strategy

- **Negative tests**: Verify rejection of invalid certificates, expired certs, wrong SNI.
- **Amplification**: Verify server never exceeds 3x before validation.
- **Replay**: Verify 0-RTT replay detection mechanisms.
- **DoS resilience**: Stress test with many connections, rapid stream creation.
- **Timing**: Verify constant-time operations (statistical timing analysis).
- **Interop**: Verify handshake against reference implementations with various cipher suites.

---


## 6. References

- RFC 9000 Section 21 (Security Considerations): https://www.rfc-editor.org/rfc/rfc9000#section-21
- RFC 9001 Section 9 (Security Considerations): https://www.rfc-editor.org/rfc/rfc9001#section-9
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 8999 (QUIC Invariants): https://www.rfc-editor.org/rfc/rfc8999
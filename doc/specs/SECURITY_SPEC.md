# Security Specification

**Version**: 1.0-draft  
**Status**: Specification  
**RFC Basis**: RFC 9000 Section 21, RFC 9001 Section 9, RFC 8446  
**Subsystem**: Security Model & Threat Mitigation

---

## 1. Purpose

This document specifies the security model for `dart_quic`: threat model, TLS 1.3 requirements, certificate handling, protection against amplification, replay, downgrade, and denial-of-service attacks.

---

## 2. Threat Model

### 2.1 Attacker Capabilities

| Attacker Type | Capabilities | Threat Level |
|--------------|-------------|--------------|
| **Passive on-path** | Observe all packets; cannot modify or inject | Medium |
| **Active on-path** | Observe, modify, inject, drop packets | High |
| **Off-path** | Cannot observe traffic; can send spoofed packets | Low-Medium |
| **Compromised peer** | Controls one endpoint; may violate protocol | High |

### 2.2 Assets to Protect

| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|--------------|
| Application data | Required | Required | Required |
| Handshake data | Partial (Initial visible) | Required | Required |
| Connection metadata | Best-effort | Required | Required |
| Peer identity | Required (for libp2p) | Required | Required |
| Session keys | Critical | Critical | Required |

---

## 3. TLS 1.3 Requirements

### 3.1 Mandatory Cipher Suites

The implementation MUST support:
- `TLS_AES_128_GCM_SHA256` (mandatory per RFC 9001)

The implementation SHOULD support:
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

### 3.2 TLS Version

- MUST use TLS 1.3 or higher.
- MUST NOT negotiate TLS 1.2 or lower.
- MUST reject connections attempting downgrade.

### 3.3 Key Exchange

- MUST support X25519.
- SHOULD support P-256 (secp256r1).
- MAY support X448, P-384, P-521.

### 3.4 Signature Algorithms

- MUST support Ed25519, ECDSA with P-256.
- SHOULD support RSA-PSS (>= 2048 bits).

---

## 4. Certificate Handling

### 4.1 Standard QUIC (non-libp2p)

- Server MUST present a valid certificate chain.
- Client MUST validate:
  - Certificate chain up to a trusted CA root.
  - Server name (SNI) matches certificate Subject Alternative Name.
  - Certificate is not expired or revoked.
  - Certificate public key meets minimum strength requirements.

### 4.2 libp2p Mode

- Both peers present self-signed certificates (Section 4 of LIBP2P_QUIC_SPEC.md).
- Validation is against the libp2p Public Key Extension, not CA chains.
- Peer ID is the trust anchor.

### 4.3 Certificate Storage

- Private keys MUST be held in memory only during the connection lifetime.
- No plaintext key material on disk.
- Dart `SecurityContext` handles key loading from PEM/DER files.

---

## 5. Amplification Protection (RFC 9000 Section 8)

### 5.1 Server Anti-Amplification

Before address validation, the server MUST NOT send more than **3 times** the number of bytes received from the client:

```
max_bytes = 3 * bytes_received_from_client
```

### 5.2 Address Validation Mechanisms

| Mechanism | When Used | How |
|-----------|-----------|-----|
| Retry token | On Initial packet | Server sends Retry; client proves it received it |
| PATH_RESPONSE | Connection migration | Peer proves it's at the new address |
| Handshake completion | After handshake | Client has been validated by completing TLS |
| NEW_TOKEN | Future connections | Server provides token for future use |

### 5.3 Initial Packet Padding

Client's first Initial packet MUST be padded to at least **1200 bytes**:
```dart
if (isInitialPacket && totalSize < 1200) {
  addPaddingFrames(1200 - totalSize);
}
```

This ensures the client sends enough data for the server's 3x amplification limit to permit a full response.

---

## 6. Replay Protection

### 6.1 0-RTT Replay

0-RTT data is inherently replayable because it is encrypted with keys derived from a previous session. Mitigations:

| Strategy | Implementation |
|----------|---------------|
| **Idempotent-only** | Only allow safe HTTP methods (GET, HEAD) in 0-RTT |
| **Single-use tickets** | Server invalidates session ticket after first use |
| **Time window** | Reject 0-RTT data older than a configured threshold |
| **Application awareness** | API clearly marks data as 0-RTT; app decides safety |

### 6.2 Dart API Marking

```dart
class QuicStream {
  /// Whether this stream carries 0-RTT (potentially replayable) data.
  bool get isEarlyData;
}
```

---

## 7. Downgrade Protection

### 7.1 Version Downgrade

- QUIC Version Negotiation uses integrity protection (RFC 8999).
- The `version` field in packet headers is authenticated by packet protection.
- An attacker cannot trick endpoints into using an older QUIC version.

### 7.2 TLS Downgrade

- TLS 1.3's downgrade sentinel (in ServerHello.random) prevents TLS version downgrade.
- QUIC MUST NOT use TLS versions below 1.3.

### 7.3 Cipher Suite Downgrade

- Client and server negotiate cipher suites via TLS 1.3's normal mechanism.
- The negotiated cipher suite is covered by the Finished MAC — tampering is detected.

---

## 8. Denial-of-Service Protection

### 8.1 Connection-Level DoS

| Attack | Mitigation |
|--------|-----------|
| SYN flood (Initial flood) | Retry tokens; amortize per-connection state |
| Slowloris (slow handshake) | Handshake timeout; limit concurrent handshakes |
| Resource exhaustion | Limit max connections per IP; memory budgets |

### 8.2 Stream-Level DoS

| Attack | Mitigation |
|--------|-----------|
| Stream flood | Enforce MAX_STREAMS; rate-limit stream creation |
| Data flood | Flow control limits (MAX_DATA, MAX_STREAM_DATA) |
| RESET_STREAM flood | Rate-limit resets; close connection on abuse |
| Header bomb | SETTINGS_MAX_FIELD_SECTION_SIZE |

### 8.3 Implementation Limits

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

## 9. Connection ID Security

### 9.1 Linkability Prevention

- Endpoints use NEW_CONNECTION_ID to provide multiple CIDs.
- After migration, old CID is retired (RETIRE_CONNECTION_ID).
- On-path observers cannot link activity across network changes.

### 9.2 Stateless Reset

- If an endpoint loses state, it can send a Stateless Reset.
- The reset token is derived from the CID using a static key known only to the endpoint.
- Prevents off-path attackers from forging resets.

```
reset_token = HMAC-SHA256(static_key, connection_id)[0..16]
```

---

## 10. Timing Side-Channels

### 10.1 Constant-Time Operations

The following MUST be constant-time:
- AEAD tag comparison (authentication verification).
- HMAC comparison (for stateless reset tokens).
- Certificate signature verification result comparison.

### 10.2 Timing Leak Prevention

- Do NOT branch on secret data.
- Use Dart's secure comparison utilities where available.
- Consider packet processing time uniformity (pad to fixed time if necessary for high-security deployments).

---

## 11. Randomness Requirements

| Usage | Source | Quality |
|-------|--------|---------|
| Connection IDs | `Random.secure()` | Cryptographically secure |
| PATH_CHALLENGE data | `Random.secure()` | Cryptographically secure |
| Retry token nonce | `Random.secure()` | Cryptographically secure |
| TLS key shares | Crypto library | Cryptographically secure |
| Packet number (initial) | `Random.secure()` | Unpredictable start |

NEVER use `Random()` (non-secure) for any security-relevant value.

---

## 12. Logging and Diagnostics

### 12.1 Safe Logging

| Data | Log Level | Allowed? |
|------|-----------|----------|
| Connection IDs | Debug | Yes |
| Packet numbers | Trace | Yes |
| Frame types | Debug | Yes |
| Header values | — | **NO** (may contain auth tokens) |
| Key material | — | **NEVER** |
| Certificate data | Debug | Fingerprint only |
| Error messages | Info | Yes (sanitized) |

### 12.2 Audit Trail

Log security-relevant events:
- Connection establishment (peer identity, cipher suite).
- Certificate validation failures.
- Authentication failures.
- Anomalous behavior (too many resets, address spoofing attempts).

---

## 13. Acceptance Criteria

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

## 14. Dependencies

- TLS 1.3 engine (crypto subsystem).
- Wire codec (packet headers for protection).
- Connection manager (amplification limits, handshake timeouts).
- Dart `Random.secure()`.
- `package:cryptography` for HMAC, AEAD.

---

## 15. Testing Strategy

- **Negative tests**: Verify rejection of invalid certificates, expired certs, wrong SNI.
- **Amplification**: Verify server never exceeds 3x before validation.
- **Replay**: Verify 0-RTT replay detection mechanisms.
- **DoS resilience**: Stress test with many connections, rapid stream creation.
- **Timing**: Verify constant-time operations (statistical timing analysis).
- **Interop**: Verify handshake against reference implementations with various cipher suites.

---

## References

- RFC 9000 Section 21 (Security Considerations): https://www.rfc-editor.org/rfc/rfc9000#section-21
- RFC 9001 Section 9 (Security Considerations): https://www.rfc-editor.org/rfc/rfc9001#section-9
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 8999 (QUIC Invariants): https://www.rfc-editor.org/rfc/rfc8999

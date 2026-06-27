---
title: "RFC 9001 Notes: Using TLS to Secure QUIC"
category: research
authors: "M. Thomson (Ed.), S. Turner (Ed.)"
published: "May 2021"
companion_rfcs: []
---

# RFC 9001 Notes: Using TLS to Secure QUIC


---

## 1. Purpose

QUIC replaces the TLS record layer entirely, carrying handshake messages in CRYPTO frames and deriving packet-protection keys via HKDF. This architectural shift is easy to misunderstand-especially around encryption levels, nonce construction, and header protection. These notes ensure the crypto and wire teams share the same mental model.

## 2. Abstract

RFC 9001 describes how TLS 1.3 is used to secure QUIC connections. QUIC takes over the responsibilities of the TLS record layer — TLS handshake and alert messages are carried directly in QUIC CRYPTO frames rather than in TLS records.

---


## 3. Architecture: QUIC + TLS Integration

```
+------------+                        +------------+
|    TLS     |--- handshake msgs ---->|    TLS     |
| (endpoint) |<--- handshake msgs ----|  (endpoint)|
+-----+------+                        +-----+------+
      |  ^                                   |  ^
      |  | (secrets)                         |  | (secrets)
      v  |                                   v  |
+-----+------+                        +-----+------+
|   QUIC     |====== QUIC packets ====|   QUIC     |
| (transport)|                        | (transport)|
+------------+                        +------------+
```

Key architectural decision: QUIC replaces the TLS record layer entirely. TLS only provides:
1. Handshake message generation/consumption
2. Key derivation
3. Alert signaling

QUIC provides:
1. Reliable, ordered delivery of handshake messages (via CRYPTO frames)
2. Packet protection (encryption + authentication)
3. Key update mechanism

---


## 4. Encryption Levels (Section 4)

QUIC uses four encryption levels, each corresponding to a TLS epoch:

| Level | TLS Epoch | Used For | Key Source |
|-------|-----------|----------|------------|
| Initial | — | First flight, before any TLS output | Derived from client DCID |
| 0-RTT (Early Data) | early_data | Resumed session early data | `client_early_traffic_secret` |
| Handshake | handshake | Handshake completion | `client/server_handshake_traffic_secret` |
| 1-RTT (Application) | application_data | Post-handshake data | `client/server_application_traffic_secret_0` |

---


## 5. Initial Secrets Derivation (Section 5.2)

Initial secrets are **not** derived from a TLS handshake. They use a well-known salt and the client's initial Destination Connection ID. See [QUIC_CRYPTO_SPEC.md §3](../specs/QUIC_CRYPTO_SPEC.md#3-initial-secrets-and-packet-protection-rfc-9001-section-5) for the complete derivation and exact test vectors.

These provide confidentiality only against passive observers — an active attacker who sees the Initial packet can derive the same keys.

---


## 6. Key Derivation (Section 5.1)

From each traffic secret, QUIC derives:

```
key  = HKDF-Expand-Label(secret, "quic key", "", key_length)
iv   = HKDF-Expand-Label(secret, "quic iv",  "", 12)
hp   = HKDF-Expand-Label(secret, "quic hp",  "", hp_key_length)
```

- `key`: AEAD encryption key
- `iv`: Initialization vector (nonce base)
- `hp`: Header protection key

All `HKDF-Expand-Label` calls use a zero-length Context (empty string).

---


## 7. Packet Protection (Section 5.3-5.4)

### AEAD Encryption

- Nonce = `iv XOR packet_number` (packet number left-padded with zeros to 12 bytes)
- Associated Data (AD) = the QUIC packet header (up to and including the unprotected packet number)
- Plaintext = packet payload (frames)
- Ciphertext = AEAD output (payload + 16-byte authentication tag for AES-128-GCM/AES-256-GCM or Poly1305 tag for ChaCha20)

### Header Protection

Applied **after** payload encryption to obscure the packet number length and value:

1. Sample 16 bytes from the ciphertext (starting at byte 4 of the packet number field offset).
2. Use the `hp` key to generate a 5-byte mask:
   - AES-based: `mask = AES-ECB(hp_key, sample)`
   - ChaCha20-based: `mask = ChaCha20(hp_key, sample[0..3] as counter, sample[4..15] as nonce)`
3. XOR the first byte of the header with `mask[0]` (protecting flags).
4. XOR the packet number bytes with `mask[1..4]`.

---


## 8. Supported Cipher Suites (Section 5.3)

| TLS Cipher Suite | AEAD | Key Length | IV Length | HP Algorithm |
|------------------|------|------------|-----------|--------------|
| TLS_AES_128_GCM_SHA256 | AES-128-GCM | 16 | 12 | AES-ECB |
| TLS_AES_256_GCM_SHA384 | AES-256-GCM | 32 | 12 | AES-ECB |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20-Poly1305 | 32 | 12 | ChaCha20 |

---


## 9. Key Update (Section 6)

After the handshake completes, either endpoint can initiate a key update:

```
application_traffic_secret_N+1 =
    HKDF-Expand-Label(application_traffic_secret_N, "quic ku", "", Hash.length)
```

- Signaled by toggling the Key Phase bit in the short header.
- Both endpoints maintain current and next-generation keys for a transition period.
- Only one update can be in progress at a time.
- Initiator must wait for acknowledgment of a packet with the new key phase before initiating another update.

---


## 10. Retry Integrity (Section 5.8)

Retry packets use a fixed key and nonce (published in the RFC) to compute an integrity tag:

```
retry_key  = 0xbe0c690b9f66575a1d766b54e368c84e  (QUIC v1)
retry_nonce = 0x461599d35d632bf2239825bb
```

This prevents off-path modification of Retry packets while remaining stateless for the server.

---


## 11. TLS Handshake Messages in QUIC (Section 4)

TLS handshake messages are carried in CRYPTO frames at the appropriate encryption level:

| Message | Encryption Level |
|---------|-----------------|
| ClientHello | Initial |
| ServerHello | Initial |
| EncryptedExtensions | Handshake |
| CertificateRequest | Handshake |
| Certificate | Handshake |
| CertificateVerify | Handshake |
| Finished (server) | Handshake |
| Finished (client) | Handshake |
| NewSessionTicket | 1-RTT |

---


## 12. QUIC Transport Parameters TLS Extension (Section 8.2)

QUIC transport parameters are sent as a TLS extension (`quic_transport_parameters`, code point 0x0039`). Both endpoints include this extension in their handshake:

- Client: in ClientHello
- Server: in EncryptedExtensions

Parameters are encoded as a sequence of (ID, length, value) tuples.

---


## 13. Security Considerations for dart_quic

1. **Initial secrets are public**: Any observer who sees the DCID can derive Initial keys. Initial packets provide integrity but not true confidentiality.
2. **Constant-time operations**: Key derivation and packet protection must use constant-time comparisons to prevent timing attacks.
3. **Key phase bit**: Must correctly track key generations; mishandling causes connection failure.
4. **0-RTT replay**: Application must be aware that 0-RTT data can be replayed; Dart API should clearly mark 0-RTT data.
5. **Certificate validation**: Standard X.509 certificate chain validation must be performed (or custom validation for libp2p).

---


## 14. Implementation Notes for Dart

- `package:cryptography` or `package:pointycastle` can provide AES-GCM, ChaCha20-Poly1305, and HKDF.
- Header protection requires either AES-ECB (single-block) or ChaCha20 (5-byte mask generation).
- The nonce construction (XOR with packet number) is simple but must correctly left-pad.
- CRYPTO frames must be reassembled in order within each encryption level (QUIC guarantees this per-level).

---


## 15. References

- RFC 9001: https://www.rfc-editor.org/rfc/rfc9001
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
# QUIC Cryptographic Specification

**Version**: 1.0-draft  
**Status**: Specification  
**RFC Basis**: RFC 9001, RFC 8446 (TLS 1.3), RFC 5869 (HKDF)  
**Subsystem**: Packet Protection & Key Management

---

## 1. Purpose

This document specifies the cryptographic operations for `dart_quic`: TLS 1.3 integration, key derivation, packet protection (AEAD encryption), header protection, key updates, and Initial secret computation.

---

## 2. TLS 1.3 Integration Architecture

### 2.1 Layering

```
┌────────────────────────────────┐
│         TLS 1.3 Engine         │  (handshake message generation)
│   - ClientHello/ServerHello    │
│   - Certificate/CertVerify     │
│   - Finished                   │
├────────────────────────────────┤
│       QUIC-TLS Interface       │  (maps TLS events to QUIC actions)
│   - Emit CRYPTO frames         │
│   - Install new keys           │
│   - Provide transport params   │
├────────────────────────────────┤
│      QUIC Packet Protection    │  (AEAD encrypt/decrypt)
│   - Header protection          │
│   - Nonce construction         │
│   - Key phase tracking         │
└────────────────────────────────┘
```

### 2.2 TLS-QUIC Interface Contract

The TLS engine MUST provide to QUIC:
1. Handshake bytes to send (per encryption level).
2. Traffic secrets when available (Initial → Handshake → 1-RTT).
3. AEAD algorithm selection.
4. Transport parameters to include in the TLS extension.

QUIC MUST provide to TLS:
1. Received handshake bytes (per encryption level).
2. Transport parameters received from the peer.

---

## 3. Encryption Levels

| Level | Secret Derivation | Lifetime |
|-------|-------------------|----------|
| Initial | From DCID + fixed salt | Until Handshake keys available |
| 0-RTT | From `client_early_traffic_secret` | Until 1-RTT keys available |
| Handshake | From `client/server_handshake_traffic_secret` | Until handshake confirmed |
| 1-RTT | From `client/server_application_traffic_secret_0` | Connection lifetime |

---

## 4. Initial Secrets (RFC 9001 Section 5.2)

### 4.1 Derivation

```
// QUIC v1 initial salt (fixed, published in RFC)
initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a

// PRK from client's initial Destination Connection ID
initial_secret = HKDF-Extract(
  salt: initial_salt,
  IKM: client_dst_connection_id
)

// Derive per-direction secrets
client_initial_secret = HKDF-Expand-Label(
  secret: initial_secret,
  label: "client in",
  context: "",
  length: 32
)

server_initial_secret = HKDF-Expand-Label(
  secret: initial_secret,
  label: "server in",
  context: "",
  length: 32
)
```

### 4.2 HKDF-Expand-Label

```
HKDF-Expand-Label(Secret, Label, Context, Length):
  HkdfLabel = struct {
    uint16 length = Length
    opaque label<7..255> = "tls13 " + Label
    opaque context<0..255> = Context
  }
  return HKDF-Expand(Secret, HkdfLabel, Length)
```

Note: All QUIC usages of HKDF-Expand-Label use a **zero-length Context**.

---

## 5. Key Derivation from Secrets (RFC 9001 Section 5.1)

From each traffic secret, derive:

```
key = HKDF-Expand-Label(secret, "quic key", "", key_length)
iv  = HKDF-Expand-Label(secret, "quic iv",  "", 12)
hp  = HKDF-Expand-Label(secret, "quic hp",  "", hp_key_length)
```

| Cipher Suite | key_length | hp_key_length | AEAD |
|-------------|-----------|---------------|------|
| TLS_AES_128_GCM_SHA256 | 16 | 16 | AES-128-GCM |
| TLS_AES_256_GCM_SHA384 | 32 | 32 | AES-256-GCM |
| TLS_CHACHA20_POLY1305_SHA256 | 32 | 32 | ChaCha20-Poly1305 |

---

## 6. Packet Protection (AEAD)

### 6.1 Nonce Construction (RFC 9001 Section 5.3)

```
nonce = iv XOR pad_left(packet_number, 12)
```

- `packet_number` is the full (reconstructed) packet number.
- Left-padded with zeros to 12 bytes.
- XOR with the 12-byte IV.

### 6.2 Encryption

```
ciphertext = AEAD-Encrypt(key, nonce, aad, plaintext)
```

- **AAD** (Associated Data): The QUIC packet header, from the first byte up to and including the (unprotected) packet number field.
- **Plaintext**: The packet payload (frames).
- **Output**: Ciphertext + authentication tag (16 bytes for AES-GCM, 16 bytes for ChaCha20-Poly1305).

### 6.3 Decryption

```
plaintext = AEAD-Decrypt(key, nonce, aad, ciphertext)
```

If decryption fails (authentication tag mismatch), the packet MUST be discarded silently.

---

## 7. Header Protection (RFC 9001 Section 5.4)

### 7.1 Purpose

Header protection obscures the packet number and certain flag bits from observers who don't possess the header protection key.

### 7.2 Algorithm

**Applied after encryption (sender) / removed before decryption (receiver).**

#### Step 1: Sample

Take a 16-byte sample from the ciphertext:
```
sample_offset = pn_offset + 4  // 4 bytes after packet number start
sample = ciphertext[sample_offset .. sample_offset + 16]
```

#### Step 2: Generate Mask

For **AES-based** cipher suites:
```
mask = AES-ECB-Encrypt(hp_key, sample)[0..5]  // first 5 bytes
```

For **ChaCha20-based** cipher suite:
```
counter = sample[0..4] as little-endian uint32
nonce = sample[4..16]
mask = ChaCha20(hp_key, counter, nonce, [0,0,0,0,0])[0..5]
```

#### Step 3: Apply Mask

```
// Long header: mask 4 bits of first byte
header[0] ^= mask[0] & 0x0F

// Short header: mask 5 bits of first byte
header[0] ^= mask[0] & 0x1F

// Mask packet number bytes (1-4 bytes based on pn_length)
pn_length = (header[0] & 0x03) + 1  // after unmasking
for i in 0..pn_length:
  header[pn_offset + i] ^= mask[1 + i]
```

---

## 8. Key Update (RFC 9001 Section 6)

### 8.1 Derivation

```
application_traffic_secret_N+1 = HKDF-Expand-Label(
  secret: application_traffic_secret_N,
  label: "quic ku",
  context: "",
  length: Hash.length
)
```

Then derive new `key` and `iv` from the new secret (same as Section 5).

### 8.2 Key Phase Bit

- The Key Phase bit in the short header toggles on each key update.
- Both endpoints track the current and previous key generation.
- A received packet with a different Key Phase bit triggers use of the next-generation keys.

### 8.3 Constraints

- Only one key update may be in progress at a time.
- Initiator must receive an ACK for a packet sent with the new keys before initiating another update.
- Old keys are retained briefly to handle reordered packets.

---

## 9. Retry Integrity Tag (RFC 9001 Section 5.8)

```
// QUIC v1 fixed key and nonce
retry_key   = 0xbe0c690b9f66575a1d766b54e368c84e
retry_nonce = 0x461599d35d632bf2239825bb

// Pseudo-Retry packet (includes original DCID)
pseudo_retry = original_dcid_length || original_dcid || retry_packet_without_tag

// Compute tag
retry_integrity_tag = AES-128-GCM-Encrypt(retry_key, retry_nonce, pseudo_retry, "")
// (empty plaintext; the tag is the output)
```

---

## 10. Acceptance Criteria

- [ ] Initial secret derivation matches RFC 9001 Appendix A test vectors.
- [ ] HKDF-Expand-Label produces correct output for known inputs.
- [ ] AES-128-GCM encrypt/decrypt round-trips correctly.
- [ ] ChaCha20-Poly1305 encrypt/decrypt round-trips correctly.
- [ ] Header protection apply/remove round-trips correctly.
- [ ] Key update produces correct next-generation secrets.
- [ ] Retry integrity tag validates correctly.
- [ ] Nonce construction handles all packet number lengths.
- [ ] Decryption failure returns error (not crash).
- [ ] Timing-safe comparison for authentication tags.

---

## 11. Security Considerations

- **Constant-time comparisons**: All tag verification must be constant-time to prevent timing side-channels.
- **Key erasure**: Old keys should be zeroed from memory after the transition period.
- **Initial key visibility**: Initial keys are derivable from the DCID — Initial packets do not provide confidentiality against active observers.
- **Nonce uniqueness**: Packet numbers must never be reused with the same key; the protocol guarantees this by monotonically increasing packet numbers.
- **Random number generation**: Dart's `Random.secure()` must be used for all cryptographic randomness.

---

## 12. Dependencies

- `package:cryptography` (preferred): AES-GCM, ChaCha20-Poly1305, HKDF, SHA-256/384.
- `package:pointycastle` (fallback): AES-ECB for header protection, HKDF.
- Wire codec (QUIC_WIRE_SPEC.md): Packet parsing/serialization.

---

## 13. Testing Strategy

- RFC 9001 Appendix A test vectors (Initial secret derivation, packet protection).
- Cross-implementation validation against aioquic, quic-go packet captures.
- Fuzz testing: Random ciphertext must not cause crashes.
- Performance benchmarks: Encrypt/decrypt throughput in packets/second.

---

## References

- RFC 9001: https://www.rfc-editor.org/rfc/rfc9001
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- RFC 9001 Appendix A (Test Vectors): https://www.rfc-editor.org/rfc/rfc9001#appendix-A

---
title: "QUIC RFC Test Vectors"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Unknown"
rfc_basis: []
dependencies:
  - "TESTING_SPEC.md"
---

# QUIC RFC Test Vectors


## 1. Purpose

Cryptographic implementations are notoriously sensitive to off-by-one errors and endianness mistakes. RFC-published test vectors provide ground-truth inputs and outputs that any compliant implementation must reproduce exactly. This document collects those vectors so that dart_quic developers can verify correctness without relying on peer interop alone.

## 2. Overview

All vectors in this document are reproduced from:

- **RFC 9001** *Using TLS to Secure QUIC*, Appendix A: sample packet protection for Initial and Retry packets.
- **RFC 9001** §5.2: derivation of Initial secrets from the client-chosen Destination Connection ID.
- **RFC 9000** *QUIC: A UDP-Based Multiplexed and Secure Transport*, §16 and Appendix A.1: variable-length integer encoding and decoding.

The canonical example uses an 8-byte client Destination Connection ID:

```text
DCID = 0x8394c8f03e515708
```

All values are shown in hexadecimal with no spaces unless otherwise noted.

---





## 3. Detailed Specification

### 3.1 Initial Secret Derivation (RFC 9001 §5.2)

The Initial salt is a fixed version-1 constant (RFC 9001 §5.2):

```text
initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
```

Using the client-chosen DCID `0x8394c8f03e515708`:

```text
initial_secret = HKDF-Extract(initial_salt, DCID)
    = 0x7db5df06e7a69e432496adedb0085192
      3595221596ae2ae9fb8115c1e9ed0a44

client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    = 0xc00cf151ca5be075ed0ebfb5c80323c4
      2d6b7db67881289af4008f1f6c357aea

server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    = 0x3c199828fd139efd216c155ad844cc81
      fb82fa8d7446fa7d78be803acdda951b
```

From the client Initial secret the packet-protection keys are derived:

```text
client_key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
    = 0x1f369613dd76d5467730efcbe3b1a22d

client_iv  = HKDF-Expand-Label(client_initial_secret, "quic iv",  "", 12)
    = 0xfa044b2f42a3fd3b46fb255c

client_hp  = HKDF-Expand-Label(client_initial_secret, "quic hp",  "", 16)
    = 0x9f50449e04a0e810283a1e9933adedd2
```

From the server Initial secret the packet-protection keys are derived:

```text
server_key = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
    = 0xcf3a5331653c364c88f0f379b6067e37

server_iv  = HKDF-Expand-Label(server_initial_secret, "quic iv",  "", 12)
    = 0x0ac1493ca1905853b0bba03e

server_hp  = HKDF-Expand-Label(server_initial_secret, "quic hp",  "", 16)
    = 0xc206b8d9b9f0f37644430b490eeaa314
```

The HKDF-Expand-Label input is SHA-256. The labels as they appear inside the `HkdfLabel` structure are:

| Label | Hex representation inside HkdfLabel |
|-------|-------------------------------------|
| `client in` | `00200f746c73313320636c69656e7420696e00` |
| `server in` | `00200f746c7331332073657276657220696e00` |
| `quic key`  | `00100e746c7331332071756963206b657900` |
| `quic iv`   | `000c0d746c733133207175696320697600` |
| `quic hp`   | `00100d746c733133207175696320687000` |

---


### 3.2 Initial Packet Protection (RFC 9001 Appendix A.2)

This example shows the full Client Initial packet for the DCID above. The packet is padded with PADDING frames to reach a 1162-byte payload; the total protected length (packet number + payload + auth tag) is 1182 bytes.

#### 3.2.1 Unprotected Payload

```text
060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408 050806002d00020101001c0002400100
3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806 048000ffff
```

followed by `0x00` repeated 917 times (PADDING frames).

#### 3.2.2 Unprotected Header

The unprotected header indicates a length of 1182 bytes and packet number 2:

```text
c300000001088394c8f03e5157080000449e00000002
```

#### 3.2.3 Header Protection Sample and Mask

After encrypting the payload, the first 16 bytes of the protected payload are used as the header-protection sample:

```text
sample = 0xd1b1c98dd7689fb8ec11d242b123dc9b
mask   = AES-ECB(client_hp, sample)[0..4]
       = 0x437b9aec36

header[0]      ^= mask[0] & 0x0f  => 0xc0
header[18..21] ^= mask[1..4]      => 0x7b9aec34
protected header = c000000001088394c8f03e5157080000449e7b9aec34
```

#### 3.2.4 Final Protected Packet

The complete wire-format Client Initial packet is:

```text
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
```

---


### 3.3 Variable-Length Integer Test Vectors (RFC 9000 §16 / Appendix A.1)

RFC 9000 §16 defines the encoding format. The two most significant bits of the first byte encode the length. Explicit decode examples are given in RFC 9000 Appendix A.1.

#### 3.3.1 Encoding Format (RFC 9000 §16)

| 2MSB | Total Length | Usable Bits | Maximum Value |
|------|--------------|-------------|---------------|
| `00` | 1 byte       | 6           | 63 |
| `01` | 2 bytes      | 14          | 16,383 |
| `10` | 4 bytes      | 30          | 1,073,741,823 |
| `11` | 8 bytes      | 62          | 4,611,686,018,427,387,903 |

#### 3.3.2 Encode/Decode Pairs

| Decimal Value | Encoded Hex | Encoding Width |
|---------------|-------------|----------------|
| 0 | `0x00` | 1 byte |
| 37 | `0x25` | 1 byte |
| 37 | `0x4025` | 2 bytes (non-minimal, valid) |
| 63 | `0x3f` | 1 byte |
| 64 | `0x4040` | 2 bytes |
| 15,293 | `0x7bbd` | 2 bytes |
| 16,383 | `0x7fff` | 2 bytes |
| 16,384 | `0x80004000` | 4 bytes |
| 494,878,333 | `0x9d7f3e7d` | 4 bytes |
| 1,073,741,823 | `0x7fffffff` | 4 bytes |
| 1,073,741,824 | `0x8000000040000000` | 8 bytes |
| 151,288,809,941,952,652 | `0xc2197c5eff14e88c` | 8 bytes |
| 4,611,686,018,427,387,903 | `0x3fffffffffffffff` | 8 bytes |

Implementations MUST decode every entry in the table to the shown decimal value and MUST encode the decimal value to the canonical minimum-width form shown (except where the protocol explicitly requires non-minimal encoding for the Frame Type field).

---


### 3.4 Retry Integrity Tag (RFC 9001 §5.8)

Retry packets use a fixed AEAD_AES_128_GCM key and nonce derived via HKDF-Expand-Label from the secret `0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e` with labels `"quic key"` and `"quic iv"`.

The fixed values are:

```text
K (secret key) = 0xbe0c690b9f66575a1d766b54e368c84e
N (nonce)      = 0x461599d35d632bf2239825bb
P (plaintext)  = empty
```

The associated data `A` is the Retry Pseudo-Packet, which prepends the Original Destination Connection ID to the Retry packet excluding the final 16-byte integrity tag. For the Client Initial in §3.2, the ODCID is `0x8394c8f03e515708` and the Retry packet body is:

```text
Retry packet (excluding tag):
    ff000000010008f067a5502a4262b5746f6b656e

Retry token:
    746f6b656e   ("token")
```

The associated data `A` is therefore:

```text
A = 0x088394c8f03e515708ff000000010008f067a5502a4262b5746f6b656e
    |  ODCID len  |  ODCID           | Retry packet body (header + token) |
```

The resulting Retry Integrity Tag is:

```text
Tag = 0x04a265ba2eff4d829058fb3f0f2496ba
```

The complete wire-format Retry packet is:

```text
ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
0f2496ba
```

---



## 4. Acceptance Criteria

- [ ] `initial_salt` matches RFC 9001 §5.2 exactly: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`.
- [ ] Deriving `initial_secret`, `client_initial_secret`, `server_initial_secret` and the per-role key/iv/hp from DCID `0x8394c8f03e515708` matches every hex string in §3.1.
- [ ] The Client Initial unprotected header, payload, header-protection mask, and final protected packet match the bytes in §3.2.
- [ ] Variable-length integer encode/decode round-trips for every pair in §3.3.
- [ ] The Retry Integrity Tag computation for the given ODCID and Retry packet body matches `0x04a265ba2eff4d829058fb3f0f2496ba`.

---





## 5. Security Considerations

The test vectors in this document are public data copied directly from RFC 9001 and RFC 9000. They are intended only for verifying correctness of protocol implementations. They MUST NOT be used as live secrets, nonces, or keys in production traffic.

---





## 6. Dependencies

- `QUIC_CRYPTO_SPEC.md` — specifies the HKDF-Expand-Label usage, Initial secret derivation, AEAD encryption, and header protection required to reproduce these vectors.
- `QUIC_WIRE_SPEC.md` — specifies the variable-length integer encoding, long-header format, and packet-number protection rules underlying these vectors.

---















## Used By

No direct spec dependents. Referenced from architecture documents.
## 7. Testing Strategy

Use byte-for-byte comparison against the hex values in this document:

1. **Unit tests**: derive each secret/key/iv/hp independently and assert equality.
2. **Integration test**: build the full Client Initial packet from the unprotected header and payload, apply header protection, and assert the final protected bytes match §3.2.
3. **Round-trip tests**: encode each integer value in §3.3 and decode each hex string, asserting equality with the original value.
4. **Retry test**: build the Retry Pseudo-Packet from the ODCID and Retry packet body, compute the AEAD_AES_128_GCM tag with the fixed key and nonce, and assert equality with the tag in §3.4.

---





## 8. References

- RFC 9001, *Using TLS to Secure QUIC*, May 2021.
  - §5.2 Initial Secrets
  - §5.8 Retry Packet Integrity
  - Appendix A: Sample Packet Protection
- RFC 9000, *QUIC: A UDP-Based Multiplexed and Secure Transport*, May 2021.
  - §16 Variable-Length Integer Encoding
  - Appendix A.1 Sample Variable-Length Integer Decoding
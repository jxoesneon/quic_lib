# libp2p QUIC Specification Notes

**Source**: libp2p/specs (GitHub)  
**Documents**: `quic/README.md`, `tls/tls.md`, `addressing/README.md`  
**Status**: Stable specification  
**Depends on**: RFC 9000, RFC 8446 (TLS 1.3), libp2p Peer ID spec

---

## Abstract

libp2p uses QUIC as a transport that combines encryption, authentication, and stream multiplexing into a single protocol. The libp2p QUIC transport eliminates the need for a separate security handshake (Noise) and stream multiplexer (mplex/yamux) — QUIC provides both natively.

---

## Architecture: libp2p over QUIC

```
┌─────────────────────────┐
│   Application Protocol  │  (e.g., Bitswap, Kademlia, GossipSub)
├─────────────────────────┤
│   libp2p Streams        │  (bidirectional, multiplexed)
├─────────────────────────┤
│   QUIC Transport        │  (RFC 9000 streams = libp2p streams)
├─────────────────────────┤
│   TLS 1.3 (in QUIC)    │  (peer authentication via certificate extension)
├─────────────────────────┤
│   UDP                   │
└─────────────────────────┘
```

Key insight: libp2p streams map **directly** to QUIC bidirectional streams. No additional framing (unlike TCP transport which needs Noise + yamux/mplex).

---

## Multiaddr Format

### Standard QUIC v1

```
/ip4/<IPv4>/udp/<port>/quic-v1
/ip6/<IPv6>/udp/<port>/quic-v1
```

Examples:
```
/ip4/192.168.1.1/udp/4001/quic-v1
/ip6/::1/udp/4001/quic-v1
```

### With Peer ID

```
/ip4/192.168.1.1/udp/4001/quic-v1/p2p/QmPeerID...
```

### Legacy (draft-29)

```
/ip4/192.168.1.1/udp/4001/quic
```

The `quic` code point refers to draft-29; `quic-v1` refers to RFC 9000. Implementations SHOULD support `quic-v1` and MAY support `quic` for backward compatibility.

---

## TLS 1.3 with Peer Authentication (tls/tls.md)

### Overview

libp2p uses standard TLS 1.3 but with a custom peer authentication mechanism. Instead of relying on a Certificate Authority (CA), peers embed their libp2p public key in a self-signed X.509 certificate extension.

### Certificate Structure

1. **Self-signed X.509 certificate** with:
   - Subject: Can be anything (typically empty or a placeholder)
   - Public key: A newly generated key pair (NOT the host key)
   - Validity: Short-lived (recommended: current time ± some margin)
   - Extension: `libp2p Public Key Extension`

2. **libp2p Public Key Extension** (OID: 1.3.6.1.4.1.53594.1.1):
   ```
   SignedKey {
     public_key: PublicKey,     // libp2p public key (protobuf-encoded)
     signature: bytes           // signature over "libp2p-tls-handshake:" + cert_public_key
   }
   ```

### Authentication Flow

```
Client                                    Server
  |                                         |
  |  1. Generate ephemeral key pair         |
  |  2. Create self-signed cert with        |
  |     libp2p extension (host key signed)  |
  |                                         |
  |--- TLS ClientHello --------------------->|
  |                                         |
  |<--- TLS ServerHello + Certificate ------|
  |     (contains server's libp2p ext)      |
  |                                         |
  |--- TLS Certificate ------------------->|
  |     (contains client's libp2p ext)      |
  |                                         |
  |--- TLS Finished ----------------------->|
  |<--- TLS Finished ----------------------|
  |                                         |
  |  3. Both sides verify:                  |
  |     - Certificate signature valid       |
  |     - Extension signature valid         |
  |     - Derived Peer ID matches expected  |
```

### Verification Steps

1. Verify the X.509 certificate is self-signed and structurally valid.
2. Extract the `libp2p Public Key Extension`.
3. Verify the signature in the extension covers `"libp2p-tls-handshake:" || cert_public_key_DER`.
4. Derive the Peer ID from the extracted public key.
5. (Client only) Verify the derived Peer ID matches the expected peer (from the multiaddr).

### Supported Key Types

| Key Type | Multihash Code | Notes |
|----------|---------------|-------|
| Ed25519 | 0x1300 | Preferred; identity multihash if <= 42 bytes |
| Secp256k1 | 0xe7 | Used by Ethereum nodes |
| ECDSA (P-256) | 0x1200 | Standard NIST curve |
| RSA | 0x1205 | Legacy; >= 2048 bits |

---

## ALPN (Application-Layer Protocol Negotiation)

libp2p QUIC uses the ALPN token: `"libp2p"`

This is sent during the TLS handshake to identify the connection as a libp2p connection.

---

## Stream Mapping

| libp2p Concept | QUIC Mechanism |
|----------------|---------------|
| libp2p stream | QUIC bidirectional stream |
| Stream open | Open new QUIC bidi stream |
| Stream close | FIN on the QUIC stream |
| Stream reset | RESET_STREAM frame |
| Muxer negotiation | Not needed (QUIC provides natively) |

### Protocol Negotiation on Streams

Each libp2p stream still uses multistream-select (or its successor) for protocol negotiation:

```
[QUIC stream opens]
Client: /multistream/1.0.0\n
Server: /multistream/1.0.0\n
Client: /ipfs/bitswap/1.2.0\n
Server: /ipfs/bitswap/1.2.0\n
[application data]
```

---

## NAT Traversal Considerations

- **UDP hole punching**: libp2p defines a hole-punching protocol (Circuit Relay v2 + DCUtR) that works with QUIC.
- **Connection migration**: QUIC's connection migration can maintain connections across NAT rebinding.
- **Relay**: libp2p Circuit Relay can tunnel QUIC connections through relay nodes.

---

## Differences from Standard QUIC/TLS Usage

| Aspect | Standard QUIC | libp2p QUIC |
|--------|---------------|-------------|
| Certificate validation | CA-based chain | Self-signed + extension verification |
| Server identity | DNS name in certificate | Peer ID derived from public key |
| ALPN | Application-specific (e.g., "h3") | `"libp2p"` |
| Client authentication | Optional | Mandatory (mutual TLS) |
| Stream usage | Application-defined | multistream-select negotiation per stream |
| Unidirectional streams | Used by HTTP/3 | Generally not used |

---

## Relevance to dart_quic

1. **Custom TLS verifier**: Must implement a TLS certificate verifier that:
   - Accepts self-signed certificates.
   - Parses the libp2p Public Key Extension.
   - Verifies the extension signature.
   - Derives and validates the Peer ID.
2. **Certificate generation**: Must generate ephemeral certificates with the extension.
3. **ALPN configuration**: Set ALPN to `"libp2p"` for libp2p connections.
4. **Mutual TLS**: Both client and server must present certificates.
5. **Key type support**: At minimum Ed25519; ideally also Secp256k1 and ECDSA.
6. **Multiaddr parsing**: Parse `/udp/.../quic-v1` multiaddr format.
7. **No Noise/mplex**: The QUIC transport replaces both the security layer and the muxer.
8. **Dart crypto**: Use `package:cryptography` for Ed25519, `package:pointycastle` for Secp256k1/ECDSA.

---

## References

- libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
- libp2p QUIC: https://libp2p.io/docs/quic/
- libp2p Addressing: https://github.com/libp2p/specs/blob/master/addressing/README.md
- libp2p Peer ID: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
- Multiaddr: https://multiformats.io/multiaddr/

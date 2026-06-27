# libp2p QUIC Transport Specification

**Version**: 1.0-draft  
**Status**: Specification  
**Basis**: libp2p/specs (tls/tls.md, quic/), RFC 9000  
**Subsystem**: libp2p QUIC Integration

---

## 1. Purpose

This document specifies the libp2p QUIC transport adapter for `dart_quic`: multiaddr parsing, TLS 1.3 with libp2p peer authentication (self-signed certificates with public key extension), stream mapping, and integration with the libp2p protocol negotiation stack.

---

## 2. Architecture

```
┌─────────────────────────────────────┐
│      libp2p Protocol Layer          │  (Bitswap, Kademlia, GossipSub...)
├─────────────────────────────────────┤
│      multistream-select             │  (protocol negotiation per stream)
├─────────────────────────────────────┤
│      libp2p QUIC Adapter            │  (this spec)
│  - Peer authentication             │
│  - Multiaddr handling              │
│  - Stream lifecycle                │
├─────────────────────────────────────┤
│      QUIC Transport                 │  (RFC 9000, dart_quic core)
├─────────────────────────────────────┤
│      TLS 1.3                        │  (with libp2p extension)
├─────────────────────────────────────┤
│      UDP                            │  (RawDatagramSocket)
└─────────────────────────────────────┘
```

---

## 3. Multiaddr Format

### 3.1 Supported Formats

```
/ip4/<addr>/udp/<port>/quic-v1
/ip6/<addr>/udp/<port>/quic-v1
/ip4/<addr>/udp/<port>/quic-v1/p2p/<peer-id>
/ip6/<addr>/udp/<port>/quic-v1/p2p/<peer-id>
```

### 3.2 Component Codes

| Component | Code | Size |
|-----------|------|------|
| ip4 | 0x04 | 4 bytes |
| ip6 | 0x29 | 16 bytes |
| udp | 0x0111 | 2 bytes (port) |
| quic-v1 | 0xcc | 0 bytes |
| p2p | 0x01a5 | variable (multihash) |

### 3.3 Parsing

```dart
class QuicMultiaddr {
  final InternetAddress address;  // IPv4 or IPv6
  final int port;
  final PeerId? peerId;           // optional
  
  factory QuicMultiaddr.parse(String multiaddr) { ... }
  String encode() => '/ip4/$address/udp/$port/quic-v1${peerId != null ? "/p2p/$peerId" : ""}';
}
```

---

## 4. TLS 1.3 Peer Authentication

### 4.1 Certificate Generation

Each endpoint generates a certificate for each connection:

```dart
class Libp2pCertificate {
  /// Generate a self-signed X.509 certificate with libp2p extension
  static X509Certificate generate({
    required PrivateKey hostKey,    // The node's persistent identity key
    required PublicKey hostPubKey,
  }) {
    // 1. Generate ephemeral key pair for the certificate
    ephemeralKeyPair = generateKeyPair(algorithm: ECDSA_P256);
    
    // 2. Create the libp2p extension
    extension = createLibp2pExtension(hostKey, hostPubKey, ephemeralKeyPair.public);
    
    // 3. Self-sign the certificate with the ephemeral private key
    cert = X509Certificate(
      subject: "CN=libp2p",
      publicKey: ephemeralKeyPair.public,
      validity: (now - 1.hour, now + 24.hours),
      extensions: [extension],
      signedWith: ephemeralKeyPair.private,
    );
    
    return cert;
  }
}
```

### 4.2 libp2p Public Key Extension

**OID**: 1.3.6.1.4.1.53594.1.1

```
SignedKey {
  PublicKey public_key;   // protobuf-encoded libp2p public key
  bytes signature;        // sign("libp2p-tls-handshake:" || cert_spki_der)
}
```

Where:
- `public_key`: The node's host public key (protobuf: `message PublicKey { KeyType Type = 1; bytes Data = 2; }`)
- `signature`: Host private key signs the concatenation of the string `"libp2p-tls-handshake:"` and the DER-encoded SubjectPublicKeyInfo of the certificate's public key.

### 4.3 KeyType Enum

```protobuf
enum KeyType {
  RSA = 0;
  Ed25519 = 1;
  Secp256k1 = 2;
  ECDSA = 3;
}
```

### 4.4 Verification Algorithm

```
function verify_peer_certificate(cert, expected_peer_id):
  // 1. Check certificate is self-signed
  assert cert.issuer == cert.subject
  assert cert.verify(cert.publicKey)
  
  // 2. Check validity period
  assert cert.notBefore <= now <= cert.notAfter
  
  // 3. Extract libp2p extension
  ext = cert.getExtension(OID_LIBP2P)  // 1.3.6.1.4.1.53594.1.1
  assert ext != null
  
  // 4. Decode SignedKey
  signed_key = protobuf_decode(ext.value)
  host_pub_key = decode_public_key(signed_key.public_key)
  
  // 5. Verify signature
  message = "libp2p-tls-handshake:" || cert.subjectPublicKeyInfo_DER
  assert host_pub_key.verify(message, signed_key.signature)
  
  // 6. Derive and check peer ID
  derived_peer_id = PeerId.fromPublicKey(host_pub_key)
  if expected_peer_id != null:
    assert derived_peer_id == expected_peer_id
  
  return derived_peer_id
```

---

## 5. ALPN

The ALPN (Application-Layer Protocol Negotiation) token for libp2p QUIC:

```
ALPN = "libp2p"
```

This is included in the TLS ClientHello and ServerHello. If ALPN negotiation fails, the connection MUST be aborted.

---

## 6. Connection Establishment

### 6.1 Dialing (Client)

```
1. Parse target multiaddr → (address, port, expected_peer_id)
2. Create UDP socket (or reuse existing)
3. Generate ephemeral certificate with libp2p extension
4. Initiate QUIC connection with TLS config:
   - ALPN: ["libp2p"]
   - Certificate: generated cert
   - Verify: custom verifier (Section 4.4)
   - Expected Peer ID: from multiaddr
5. Complete QUIC handshake
6. Verify peer's Peer ID from certificate
7. Connection established → return (connection, remote_peer_id)
```

### 6.2 Listening (Server)

```
1. Bind UDP socket to listen address
2. Generate ephemeral certificate with libp2p extension
3. Configure QUIC listener with TLS config:
   - ALPN: ["libp2p"]
   - Certificate: generated cert
   - Client auth: required (mutual TLS)
   - Verify: custom verifier (Section 4.4)
4. Accept incoming QUIC connections
5. Verify client's Peer ID from certificate
6. Emit (connection, remote_peer_id)
```

---

## 7. Stream Lifecycle

### 7.1 Mapping

| libp2p Operation | QUIC Operation |
|-----------------|----------------|
| Open stream | Open bidirectional QUIC stream |
| Close stream (write) | Send FIN on QUIC stream |
| Close stream (read) | Receive FIN |
| Reset stream | QUIC RESET_STREAM |
| Receive reset | QUIC STOP_SENDING |

### 7.2 Protocol Negotiation

Each new stream performs multistream-select negotiation:

```
[Stream opens]
→ /multistream/1.0.0\n
← /multistream/1.0.0\n
→ /ipfs/kad/1.0.0\n
← /ipfs/kad/1.0.0\n
[Protocol data follows]
```

### 7.3 Stream Limits

- libp2p implementations typically set high MAX_STREAMS limits (1000+).
- Each protocol instance uses one stream.
- Streams are short-lived in many protocols (single request/response).

---

## 8. Connection Properties

| Property | Value |
|----------|-------|
| Security | TLS 1.3 (mutual authentication) |
| Muxing | Native QUIC streams |
| Can upgrade | No (already complete) |
| Supports holes | No (streams are ordered byte sequences) |
| Datagrams | Possible (QUIC datagrams for unreliable transport) |

---

## 9. Peer ID Derivation

### 9.1 From Public Key

```
if encoded_pub_key.length <= 42:
  peer_id = Multihash(identity, encoded_pub_key)
else:
  peer_id = Multihash(sha2-256, sha256(encoded_pub_key))
```

### 9.2 Encoding

Peer IDs are typically represented as:
- Base58btc-encoded multihash (legacy: "Qm..." for RSA)
- Base32-encoded CIDv1 (modern: "bafz..." for Ed25519)

---

## 10. NAT Traversal

### 10.1 Relay (Circuit Relay v2)

When direct connection is not possible:
```
/ip4/<relay-addr>/udp/<relay-port>/quic-v1/p2p/<relay-id>/p2p-circuit/p2p/<target-id>
```

The relay forwards QUIC packets between peers.

### 10.2 Hole Punching (DCUtR)

1. Peers discover each other's observed addresses via relay.
2. Coordinate simultaneous connection attempts.
3. Both send Initial packets to each other's observed addresses.
4. NAT mapping is established when one side's packet reaches the other.

### 10.3 Connection Migration

QUIC connection migration can survive NAT rebinding:
- Connection ID-based identification (not 4-tuple).
- PATH_CHALLENGE / PATH_RESPONSE for validation.

---

## 11. Dart API

```dart
/// libp2p QUIC transport
abstract class Libp2pQuicTransport {
  /// Dial a remote peer
  Future<Libp2pConnection> dial(
    Multiaddr target, {
    required PrivateKey hostKey,
    PeerId? expectedPeerId,
  });
  
  /// Listen for incoming connections
  Future<Libp2pQuicListener> listen(
    Multiaddr bindAddr, {
    required PrivateKey hostKey,
  });
}

abstract class Libp2pQuicListener {
  Multiaddr get localAddr;
  Stream<Libp2pConnection> get connections;
  Future<void> close();
}

abstract class Libp2pConnection {
  PeerId get localPeerId;
  PeerId get remotePeerId;
  Multiaddr get remoteAddr;
  
  Future<Libp2pStream> openStream(String protocolId);
  Stream<Libp2pStream> get incomingStreams;
  
  Future<void> close();
}

abstract class Libp2pStream {
  String get protocolId;
  Stream<List<int>> get inbound;
  StreamSink<List<int>> get outbound;
  Future<void> close();
  Future<void> reset();
}
```

---

## 12. Acceptance Criteria

- [ ] Multiaddr parsing handles all valid `/udp/.../quic-v1` formats.
- [ ] Certificate generation produces valid X.509 with libp2p extension.
- [ ] Extension signature verification succeeds for valid certificates.
- [ ] Peer ID derivation matches reference implementations (go-libp2p).
- [ ] ALPN "libp2p" is negotiated correctly.
- [ ] Mutual TLS: both sides present and verify certificates.
- [ ] Connection fails if Peer ID does not match expected.
- [ ] Streams support multistream-select protocol negotiation.
- [ ] Multiple concurrent streams per connection work correctly.
- [ ] Ed25519, Secp256k1, and ECDSA key types are supported.

---

## 13. Security Considerations

- **Certificate freshness**: Short validity periods prevent replay of old certificates.
- **Peer ID verification**: MUST always verify the derived Peer ID on the client side.
- **No CA trust**: Self-signed certificates mean the only trust anchor is the Peer ID.
- **Key type downgrade**: Accept only keys meeting minimum security requirements (RSA >= 2048 bits).
- **Extension presence**: Connections without the libp2p extension MUST be rejected.

---

## 14. Dependencies

- QUIC Transport ([QUIC_STREAMS_SPEC.md](./QUIC_STREAMS_SPEC.md), [QUIC_CRYPTO_SPEC.md](./QUIC_CRYPTO_SPEC.md)): Core QUIC connection and streams.
- Crypto (package:cryptography): Ed25519, ECDSA, X25519.
- Protobuf: For encoding/decoding the public key in the extension.
- X.509: Certificate generation and parsing.
- Multiaddr: Address parsing and encoding.

---

## 15. Testing Strategy

- Unit: Certificate generation, extension encoding/decoding, peer ID derivation.
- Integration: Full connection establishment between two dart_quic instances.
- Interop: Connect to go-libp2p QUIC nodes, verify handshake succeeds.
- Security: Reject invalid certificates, wrong peer IDs, missing extensions.
- NAT: Test relay path and hole punching coordination.

---

## References

- libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
- libp2p QUIC: https://github.com/libp2p/specs/tree/master/quic
- libp2p Peer IDs: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
- libp2p Addressing: https://github.com/libp2p/specs/blob/master/addressing/README.md
- Multistream-select: https://github.com/libp2p/specs/blob/master/connections/README.md

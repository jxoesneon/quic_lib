---
title: "Direct Connection Upgrade through Relay (DCUtR) Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "NAT Traversal"
rfc_basis: []
dependencies:
  - "LIBP2P_QUIC_SPEC.md"
  - "VERSIONING_POLICY.md"
---

# Direct Connection Upgrade through Relay (DCUtR) Specification


## 1. Purpose

NATs and firewalls prevent direct peer-to-peer QUIC connections in the majority of real-world deployments. DCUtR solves this by coordinating a simultaneous UDP hole-punch over an existing Circuit Relay v2 connection, giving dart_ipfs a path to direct, lower-latency transport even when both peers are behind NAT.

## 2. Detailed Specification
### 2.1 Protocol Overview


#### 2.1.1 Relationship to Circuit Relay v2

DCUtR is **not** a standalone transport. It operates on top of an existing relayed libp2p connection:

```
Peer A (dialer via relay)                  Peer B (inbound peer)
   │                                            │
   │─── Circuit Relay v2 connection ───────────▶│
   │◀───────────────────────────────────────────│
   │                                            │
   │─── DCUtR stream (/libp2p/dcutr) ───────────▶│  (initiated by B)
   │   CONNECT, CONNECT, SYNC exchange          │
   │                                            │
   │─── Simultaneous UDP hole-punch ────────────│
   │   A dials immediately; B sends UDP bursts  │
   │                                            │
   │◀────────── Direct QUIC connection ─────────▶│
```

The relay is used only for rendezvous and synchronization. After a successful direct connection is established, the relayed connection SHOULD be closed after a grace period, while the direct connection becomes the primary transport.


#### 2.1.2 Roles

| Role | Description | In libp2p DCUtR notation |
|------|-------------|--------------------------|
| **Initiator** | The peer that opens the DCUtR stream and sends the first `CONNECT` message. It measures the relayed RTT and sends the `SYNC` message. | Peer `B` (inbound over relay) |
| **Responder** | The peer that receives the initial `CONNECT`, replies with its own `CONNECT`, and dials immediately on receipt of `SYNC`. | Peer `A` (dialer via relay) |
| **Relay** | The Circuit Relay v2 node that forwards the relayed connection. It provides the observed addresses used in the `ObsAddrs` fields but does not participate in the DCUtR message exchange. | Third-party relay peer |

The final direct QUIC connection has a fixed client/server orientation: the **Responder** (`A`) is the QUIC client, and the **Initiator** (`B`) is the QUIC server, regardless of which peer originally dialed the relay.

---


### 2.2 Protocol Flow


#### 2.2.1 Preconditions

1. A Circuit Relay v2 reservation and relayed connection exist between the two peers.
2. Both peers have discovered at least one observed or predicted public address for the other peer, typically via the libp2p `identify` protocol or the relay's `ObsAddrs`.
3. The libp2p QUIC transport is configured for both IPv4 and IPv6 when available.


#### 2.2.2 Unilateral Upgrade Attempt

Before starting DCUtR, the Initiator MAY attempt a unilateral direct dial to one of the Responder's public addresses. If this succeeds, DCUtR is unnecessary. This step is optional and implementation-specific; it MUST NOT block the DCUtR protocol for more than a short timeout.


#### 2.2.3 DCUtR Message Exchange

The DCUtR protocol runs on a single bidirectional stream negotiated with the multistream-select protocol string `/libp2p/dcutr`.

```
Initiator (B)                              Responder (A)
   │                                            │
   │─── open /libp2p/dcutr stream ─────────────▶│
   │                                            │
   │─── HolePunch { CONNECT, ObsAddrs } ───────▶│  (start RTT timer T1)
   │                                            │
   │◀─── HolePunch { CONNECT, ObsAddrs } ───────│  (stop RTT timer; RTT = T1)
   │                                            │
   │─── HolePunch { SYNC } ────────────────────▶│  (start half-RTT timer T2)
   │                                            │
   │           Simultaneous Connect             │
   │                                            │
   │◀───────── QUIC client (A dials) ───────────│  A dials immediately
   │                                            │
   │─── UDP random-byte bursts to A ────────────│  B starts after T2 expires
   │                                            │
   │◀────────── Direct QUIC connection ─────────▶│  B is server, A is client
```


#### 2.2.4 Simultaneous Connect Details

For **QUIC addresses** obtained from `ObsAddrs`:

1. The Responder (`A`) immediately dials the Initiator's (`B`'s) address upon receiving `SYNC`.
2. The Initiator (`B`) waits for its half-RTT timer to expire, then sends UDP packets containing random bytes to `A`'s address. Packets are sent at random intervals between **10 ms and 200 ms**.
3. The UDP bursts keep `B`'s NAT mapping alive and cause inbound traffic to be accepted by `A`'s NAT, allowing `A`'s QUIC handshake to reach `B`.
4. The first successful QUIC handshake creates the direct connection. All other pending dial attempts SHOULD be cancelled.

The Initiator (`B`) SHOULD send the UDP bursts for a bounded duration (e.g., up to the direct-connection timeout) or until a direct connection is established.

---


### 2.3 Message Formats


#### 2.3.1 Framing

All DCUtR RPC messages are sent over a libp2p stream and are prefixed with their length in bytes, encoded as an unsigned variable-length integer per the [multiformats unsigned-varint spec](https://github.com/multiformats/unsigned-varint).

```
+---------------+------------------+
| uvarint length| protobuf message |
+---------------+------------------+
```

Implementations MUST reject encoded RPC messages (length prefix excluded) larger than **4 KiB**.


#### 2.3.2 Protobuf Schema

```proto
syntax = "proto2";

package holepunch.pb;

message HolePunch {
  enum Type {
    CONNECT = 100;
    SYNC    = 300;
  }

  required Type type = 1;
  repeated bytes ObsAddrs = 2;
}
```


#### 2.3.3 Field Semantics

| Field | Type | Semantics |
|-------|------|-----------|
| `type` | `required Type` | `CONNECT` (100) or `SYNC` (300). |
| `ObsAddrs` | `repeated bytes` | Binary-encoded multiaddrs of the sender's observed or predicted addresses. Used only in `CONNECT` messages. |

A `CONNECT` message MUST contain at least one `ObsAddrs` entry. A `SYNC` message MUST have no `ObsAddrs`. All addresses SHOULD be sorted with the most likely reachable addresses first (e.g., public IPv6, then public IPv4, then predicted addresses).


#### 2.3.4 Address Encoding

`ObsAddrs` entries use the binary multiaddr representation, not the string representation. For example, the string multiaddr `/ip4/198.51.100.7/udp/4001/quic-v1` is encoded as the concatenation of the protocol code and value for each component:

```
0x04 198.51.100.7 (4 bytes)
0x0111 0x0fa1      (udp port 4001, 2 bytes)
0xcc               (quic-v1, 0 bytes)
```

---


### 2.4 State Machine


#### 2.4.1 Initiator (B) State Machine

```
                    ┌──────────────┐
                    │    Start     │
                    └──────┬───────┘
                           │ open /libp2p/dcutr stream
                           ▼
                    ┌──────────────┐
                    │  ConnectSent │  send CONNECT; start RTT timer
                    └──────┬───────┘
                           │ recv CONNECT from A
                           ▼
                    ┌──────────────┐
                    │  GotConnect  │  compute RTT; send SYNC;
                    │              │  start half-RTT timer
                    └──────┬───────┘
                           │ timer expires
                           ▼
                    ┌──────────────┐
           ┌───────▶│  UDPBursting │  send random UDP packets to A's addrs
           │        └──────┬───────┘
           │               │ direct QUIC connection established
           │               ▼
           │        ┌──────────────┐
           │        │  DirectConn  │  cancel pending dials; use direct conn
           │        └──────┬───────┘
           │               │ after grace period
           │               ▼
           │        ┌──────────────┐
           │        │   Completed  │  close relay connection
           │        └──────────────┘
           │
           └──────── all addrs failed / max retries exceeded
                      ▼
               ┌──────────────┐
               │    Failed    │  keep relay connection; close DCUtR stream
               └──────────────┘
```


#### 2.4.2 Responder (A) State Machine

```
                    ┌──────────────┐
                    │    Start     │
                    └──────┬───────┘
                           │ accept /libp2p/dcutr stream
                           ▼
                    ┌──────────────┐
                    │   Listening  │
                    └──────┬───────┘
                           │ recv CONNECT from B
                           ▼
                    ┌──────────────┐
                    │  ConnectRecv │  send CONNECT with own ObsAddrs
                    └──────┬───────┘
                           │ recv SYNC
                           ▼
                    ┌──────────────┐
                    │  DialingB    │  immediately dial all B's ObsAddrs
                    └──────┬───────┘
                           │ direct QUIC connection established
                           ▼
                    ┌──────────────┐
                    │  DirectConn  │  cancel pending dials; use direct conn
                    └──────┬───────┘
                           │ after grace period
                           ▼
                    ┌──────────────┐
                    │   Completed  │  close relay connection
                    └──────────────┘
                           ▲
                           │ all addrs failed / max retries exceeded
                           ▼
                    ┌──────────────┐
                    │    Failed    │  keep relay connection; close DCUtR stream
                    └──────────────┘
```


#### 2.4.3 Transition Rules

| Event | Initiator Action | Responder Action |
|-------|-----------------|------------------|
| Stream opened | Send `CONNECT` with `ObsAddrs`. | Wait for `CONNECT`. |
| `CONNECT` received | Stop RTT timer; compute `RTT`; send `SYNC`; start half-RTT timer. | Send `CONNECT` with `ObsAddrs`. |
| `SYNC` received | (invalid at this point) abort with protocol violation. | Immediately start dialing all `ObsAddrs` from the Initiator's `CONNECT`. |
| Half-RTT timer expires | Start sending random UDP packets to all Responder `ObsAddrs`. | — |
| Direct connection established | Cancel all pending dials and UDP bursts. | Cancel all pending dials. |
| Timeout or error | Retry up to 2 additional times; otherwise fail. | Wait for Initiator to retry or abort. |

---


### 2.5 Timing and Retry Strategy


#### 2.5.1 RTT Measurement

- The Initiator measures the round-trip time (`RTT`) as the time elapsed between sending its `CONNECT` and receiving the Responder's `CONNECT`.
- The `SYNC` message is sent immediately after the Responder's `CONNECT` is received.
- The Initiator starts a half-RTT timer: `T_sync = RTT / 2`.


#### 2.5.2 Simultaneous Connect Timing

- The Responder dials the Initiator's addresses **immediately** upon receiving `SYNC`.
- The Initiator sends random UDP packets to the Responder's addresses after `T_sync` expires.
- UDP packets are sent at random intervals uniformly chosen from `[10 ms, 200 ms]`.


#### 2.5.3 Timeouts and Retry Limits

| Parameter | Recommended Value | Description |
|-----------|-------------------|-------------|
| `DCUTR_STREAM_TIMEOUT` | 30 s | Max lifetime of a single DCUtR stream. |
| `DIRECT_CONNECT_TIMEOUT` | 10 s | Max time to wait for a direct QUIC connection after `SYNC`. |
| `UDP_BURST_INTERVAL_MIN` | 10 ms | Minimum interval between random UDP packets. |
| `UDP_BURST_INTERVAL_MAX` | 200 ms | Maximum interval between random UDP packets. |
| `MAX_ATTEMPTS` | 3 | Total attempts per DCUtR session (1 initial + 2 retries). |
| `RELAY_CLOSE_GRACE_PERIOD` | 30 s | Time to keep relay connection open after direct connection success. |


#### 2.5.4 Retry Behavior

- On failure of all direct connection attempts, the Initiator SHOULD retry the entire DCUtR exchange from the beginning (open a new stream, send `CONNECT`, etc.) up to `MAX_ATTEMPTS - 1` additional times.
- Retries SHOULD re-measure the RTT because the relay path may change between attempts.
- If all attempts fail, the peers MUST keep the relayed connection active and treat DCUtR as failed.

---


### 2.6 QUIC Path Migration Considerations


#### 2.6.1 New Connection vs. Connection Migration

DCUtR establishes a **brand new** QUIC connection between the direct addresses. It does **not** migrate the existing relayed connection. The new connection is subject to normal QUIC path migration rules defined in RFC 9000 Section 9.


#### 2.6.2 Path Validation

After a direct connection is established, if either peer's network path changes (e.g., NAT rebinding), the QUIC implementation MUST perform path validation using `PATH_CHALLENGE` and `PATH_RESPONSE` frames before sending non-probing frames on the new path.


#### 2.6.3 NAT Rebinding and Connection IDs

- Because the direct connection is identified by QUIC connection IDs and not by the 4-tuple, it can survive NAT rebinding as long as the peer has supplied additional connection IDs via `NEW_CONNECTION_ID` and retired old ones via `RETIRE_CONNECTION_ID`.
- The `dart_quic` implementation SHOULD issue enough connection IDs to allow migration after a direct connection is established.


#### 2.6.4 UDP Burst Handling

- The random UDP packets sent by the Initiator are **not** valid QUIC packets; they are used solely to create NAT state.
- The Responder's QUIC listener will receive these packets on the same socket used for normal QUIC. The listener MUST ignore packets that are not valid QUIC Initial/Handshake/1-RTT packets for an active connection.
- Once the Responder's QUIC handshake reaches the Initiator, the Initiator's QUIC server accepts the new connection normally.


#### 2.6.5 Address Validation Limits

Before path validation completes, the QUIC server (Initiator) MUST respect the RFC 9000 anti-amplification limit (no more than 3x the bytes received from the new address). The Responder's QUIC Initial packet MUST be padded to at least 1200 bytes to allow the server to send a full response.

---


#### 2.6.6 Authentication

- The DCUtR stream is opened over an existing libp2p connection that has already completed mutual TLS authentication. The DCUtR implementation MUST associate the DCUtR stream with the authenticated `PeerId` of the remote peer.
- The `ObsAddrs` in `CONNECT` messages are not authenticated by DCUtR itself; they are just hints. The final direct connection MUST still perform the full libp2p TLS handshake (including the libp2p Public Key Extension) and verify the expected `PeerId` before it is used for application traffic.
- Implementations MUST reject DCUtR messages from a peer whose `PeerId` does not match the peer on the relayed connection.


#### 2.6.7 Replay Protection

- DCUtR is stateful per stream. A `CONNECT` or `SYNC` message is meaningful only within the stream in which it is sent. There is no persistent cross-stream state that an attacker could replay into.
- After a DCUtR session completes or fails, the corresponding stream is closed. Any attempt to reuse a closed stream is a QUIC protocol violation and is handled by the QUIC layer.
- The protocol does not use nonces or sequence numbers; replay protection is provided by the authenticated stream and the fact that the Initiator and Responder each choose fresh addresses per session.


#### 2.6.8 Privacy

- `ObsAddrs` may include internal or public addresses. Implementations MUST NOT log these addresses at `INFO` or higher log levels unless explicitly configured for debugging.
- The DCUtR exchange is encrypted by the relayed QUIC connection, so the relay cannot read the contents of `CONNECT` or `SYNC` messages. However, the relay already knows both endpoints of the relayed connection.
- If a direct connection is established, subsequent traffic is sent directly, hiding it from the relay.


#### 2.6.9 Denial-of-Service Mitigation

- Limit the number of concurrent DCUtR streams per peer to prevent stream-exhaustion attacks.
- Enforce the 4 KiB message size limit to avoid excessive memory allocation.
- Rate-limit retry attempts per peer to prevent aggressive reconnection loops.
- The Initiator's random UDP packets are bounded by the `DIRECT_CONNECT_TIMEOUT` and the `[10 ms, 200 ms]` interval, preventing high-volume traffic from being sent indefinitely.

---


### 2.7 Error Handling and Fallback to Relay


#### 2.7.1 Protocol Errors

| Error | Cause | Handling |
|-------|-------|----------|
| Invalid protobuf | Malformed `HolePunch` message. | Close the DCUtR stream with a protocol error; do not tear down the relay connection. |
| Missing `ObsAddrs` in `CONNECT` | `CONNECT` without addresses. | Close the DCUtR stream; fail this attempt. |
| Unexpected `SYNC` | Initiator receives `SYNC` before sending it. | Close the DCUtR stream with a protocol error. |
| Timeout | No `CONNECT` or `SYNC` received within `DCUTR_STREAM_TIMEOUT`. | Close the stream; retry if attempts remain. |
| Direct connection failure | All addresses exhausted. | Retry if attempts remain; otherwise keep relay connection. |
| Stream reset | Peer aborts the DCUtR stream. | Treat as failed attempt. |


#### 2.7.2 Fallback to Relay

- The relayed connection MUST remain usable at all times during a DCUtR attempt.
- If DCUtR fails, the peers MUST continue to use the relayed connection for new and existing streams. No application state is lost.
- The DCUtR implementation MUST notify the libp2p transport layer whether the direct upgrade succeeded or failed, so the transport can prioritize the direct connection when available.


#### 2.7.3 Graceful Migration After Success

- Once a direct connection is established and authenticated, the transport layer SHOULD:
  1. Direct all new streams to the direct connection.
  2. Allow existing streams on the relayed connection to complete naturally.
  3. Close the relayed connection after `RELAY_CLOSE_GRACE_PERIOD` or once all relayed streams have finished, whichever comes first.
- Long-lived streams that cannot be migrated by the application layer will be recreated when the relay connection closes.

---


### 2.8 Interoperability Tests Against go-libp2p

| Test | Scenario | Expected Result |
|------|----------|-----------------|
| `dcutr_quic_basic` | `dart_quic` Responder + `go-libp2p` Initiator on a relayed connection. | Direct QUIC connection established; relay closed after grace period. |
| `dcutr_quic_dart_initiator` | `dart_quic` Initiator + `go-libp2p` Responder on a relayed connection. | Direct QUIC connection established; roles (client/server) match spec. |
| `dcutr_quic_symmetric_nat` | Both peers behind symmetric NATs with a public relay. | Direct connection may fail; both peers continue using relay. |
| `dcutr_quic_retry` | First hole-punch attempt fails; retry succeeds. | Exactly one or more retries occur before success; relay remains usable. |
| `dcutr_quic_fallback` | All hole-punch attempts fail. | `dart_quic` keeps the relayed connection and reports DCUtR failed. |
| `dcutr_quic_message_format` | Capture the DCUtR stream bytes from a `go-libp2p` peer. | `dart_quic` parses `CONNECT` and `SYNC` messages identical to go-libp2p. |
| `dcutr_quic_security` | Relayed connection authenticated to a specific `PeerId`; direct dial to a different peer. | Direct connection rejected because the authenticated `PeerId` does not match. |
| `dcutr_quic_migration` | Direct connection established; then one peer's NAT rebinding occurs. | QUIC path migration completes via `PATH_CHALLENGE`/`PATH_RESPONSE`. |

---



## 3. Acceptance Criteria

- [ ] The DCUtR protocol handler is registered at `/libp2p/dcutr`.
- [ ] `CONNECT` and `SYNC` messages are encoded and decoded according to the libp2p protobuf schema.
- [ ] All messages are length-prefixed with an unsigned varint and the 4 KiB size limit is enforced.
- [ ] `ObsAddrs` are encoded as binary multiaddrs and parsed correctly.
- [ ] The Initiator measures RTT and sends `SYNC` after receiving the Responder's `CONNECT`.
- [ ] The Responder dials the Initiator's addresses immediately upon receiving `SYNC`.
- [ ] The Initiator sends random UDP packets in the `[10 ms, 200 ms]` interval after the half-RTT timer expires.
- [ ] A direct QUIC connection can be established between two NATed `dart_quic` peers via DCUtR.
- [ ] On failure, the peers fall back to the existing relayed connection and retry up to `MAX_ATTEMPTS` times.
- [ ] On success, new streams are opened on the direct connection and the relay connection is closed after a grace period.
- [ ] The direct connection still performs full libp2p TLS authentication and `PeerId` verification.
- [ ] Protocol errors on the DCUtR stream do not terminate the underlying relayed connection.

---





## 4. Security Considerations

1. **NAT Traversal Privacy**: DCUtR exposes internal IP addresses to the peer via the HOP and RSP addresses. Applications that require full IP privacy should disable DCUtR and remain on relayed connections.
2. **Relay Trust**: The relay server observes both peers' internal addresses during the cutover. Use relays under the same administrative domain or run self-hosted relays for sensitive deployments.
3. **No Authentication Bypass**: The direct connection established after DCUtR still performs the full libp2p TLS 1.3 handshake with peer certificate validation. DCUtR is purely an address-discovery mechanism; it does not bypass authentication.
4. **Amplification Mitigation**: The 4 KiB message size limit, per-peer rate limiting, and connection timeout mechanisms (\u00a72.3.1, \u00a72.6.9) prevent an attacker from using a relay to amplify traffic toward a victim address.
5. **Timing and Replay**: Each DCUtR attempt uses a fresh nonce and a monotonically increasing ttempt counter. Replay of old DCUtR/RSP frames is rejected by checking the nonce and counter against the current session state.

## Used By

- [LIBP2P_QUIC_SPEC.md](LIBP2P_QUIC_SPEC.md) — DCUtR is a required sub-protocol for libp2p QUIC direct connections.
- [VERSIONING_POLICY.md](VERSIONING_POLICY.md) — DCUtR spec is versioned under the same policy.
## 5. References

- libp2p DCUtR specification: https://github.com/libp2p/specs/blob/master/relay/DCUtR.md
- libp2p Circuit Relay v2 specification: https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
- libp2p Addressing specification: https://github.com/libp2p/specs/blob/master/addressing/README.md
- libp2p QUIC transport specification (this project): [LIBP2P_QUIC_SPEC.md](LIBP2P_QUIC_SPEC.md)
- libp2p TLS specification: https://github.com/libp2p/specs/blob/master/tls/tls.md
- RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport: https://tools.ietf.org/html/rfc9000
  - Section 8: Address Validation and Connection Establishment
  - Section 9: Connection Migration
- RFC 9001 — Using TLS to Secure QUIC: https://tools.ietf.org/html/rfc9001
- multiformats unsigned-varint: https://github.com/multiformats/unsigned-varint
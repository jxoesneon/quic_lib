# RFC 9002 Notes: QUIC Loss Detection and Congestion Control

**RFC**: 9002  
**Authors**: J. Iyengar (Ed.), I. Swett (Ed.)  
**Published**: May 2021  
**Status**: Standards Track  
**Depends on**: RFC 9000

---

## Abstract

RFC 9002 describes loss detection and congestion control mechanisms for QUIC. It specifies a loss detection algorithm based on packet number acknowledgment and a congestion controller similar to TCP NewReno.

---

## Design Context

Unlike TCP, QUIC:
- Uses **per-packet** sequence numbers (never retransmits the same packet number).
- Has **separate packet number spaces** for Initial, Handshake, and Application Data.
- Carries ACKs that are **not** congestion-controlled.
- Knows which specific packets were acknowledged (no ambiguity from retransmission).

This eliminates TCP's retransmission ambiguity and enables cleaner loss detection.

---

## RTT Measurement (Section 5)

### Variables

| Variable | Description |
|----------|-------------|
| `latest_rtt` | RTT of the most recently ack'd packet |
| `smoothed_rtt` | Exponentially weighted moving average |
| `rttvar` | RTT variation (mean deviation) |
| `min_rtt` | Minimum RTT observed (not smoothed) |

### Update Algorithm

```
On first RTT sample:
  smoothed_rtt = latest_rtt
  rttvar = latest_rtt / 2
  min_rtt = latest_rtt

On subsequent samples:
  ack_delay = min(ack_delay_field, max_ack_delay)  // clamped
  adjusted_rtt = latest_rtt
  if (latest_rtt >= min_rtt + ack_delay):
    adjusted_rtt = latest_rtt - ack_delay
  
  rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
  smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
```

---

## Loss Detection (Section 6)

### Packet Threshold

A packet is declared lost if a **newer** packet in the same packet number space has been acknowledged and the gap exceeds `kPacketThreshold` (default: 3).

```
if (largest_acked - packet.number >= kPacketThreshold):
  declare_lost(packet)
```

### Time Threshold

A packet is declared lost if sufficient time has elapsed since it was sent:

```
loss_delay = max(9/8 * max(latest_rtt, smoothed_rtt), kGranularity)
// kGranularity = 1ms (timer granularity)

if (time_since_sent > loss_delay):
  declare_lost(packet)
```

### Probe Timeout (PTO) (Section 6.2)

When no ACK is received within the PTO, the sender sends a probe to elicit an acknowledgment:

```
PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
```

- PTO probe sends new data if available, otherwise retransmits.
- PTO is armed per packet number space during handshake.
- Consecutive PTOs double the timeout (exponential backoff).
- PTO count resets when an ACK is received.

---

## Congestion Control (Section 7)

### Algorithm: NewReno-like

QUIC specifies a congestion controller similar to TCP NewReno with the following states:

| State | Condition | Behavior |
|-------|-----------|----------|
| **Slow Start** | `cwnd < ssthresh` | `cwnd += bytes_acked` per ACK |
| **Congestion Avoidance** | `cwnd >= ssthresh` | `cwnd += max_datagram_size * bytes_acked / cwnd` per ACK |
| **Recovery** | After loss detection | `ssthresh = cwnd / 2; cwnd = ssthresh` |

### Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `kInitialWindow` | `min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))` | Initial cwnd |
| `kMinimumWindow` | `2 * max_datagram_size` | Minimum cwnd after loss |
| `kPacketThreshold` | 3 | Packet reordering tolerance |
| `kTimeThreshold` | 9/8 | Time reordering factor |
| `kGranularity` | 1ms | Timer granularity |

### ECN (Explicit Congestion Notification) (Section 13.4 of RFC 9000)

- QUIC supports ECN marking (ECT(0), ECT(1), CE).
- ACK frames carry ECN counts.
- An increase in CE count triggers congestion response (same as loss).
- ECN validation: endpoints verify that ECN counts are consistent with sent packets.

---

## Persistent Congestion (Section 7.6.2)

If packets are lost over a duration exceeding the persistent congestion period, the sender assumes the path has fundamentally changed:

```
persistent_congestion_duration = 3 * (smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay)

if (duration_between_lost_packets > persistent_congestion_duration):
  cwnd = kMinimumWindow
```

This is analogous to a TCP timeout retransmission.

---

## Pacing (Section 7.7)

Recommended but not required. Sends packets at a rate matching the congestion window:

```
interval = smoothed_rtt * max_datagram_size / cwnd
```

Pacing reduces burstiness and improves fairness with other flows.

---

## Under-Utilized Connections (Section 7.8)

- If the application is not sending enough to fill the cwnd, the sender SHOULD NOT increase cwnd.
- `bytes_in_flight` must be at or near `cwnd` for congestion events to reduce the window.

---

## Per-Space vs. Per-Path

| Property | Scope |
|----------|-------|
| Loss detection | Per packet number space |
| RTT measurement | Per path (shared across spaces) |
| Congestion control | Per path (shared across spaces) |

---

## Differences from TCP Recovery

| TCP | QUIC |
|-----|------|
| Retransmits same sequence numbers | Always uses new packet numbers |
| Ambiguous RTT on retransmission | Unambiguous RTT (unique packet numbers) |
| SACK optional | ACK ranges always available |
| Single sequence space | Separate spaces per encryption level |
| Timeout uses RTO | Uses PTO (more aggressive probing) |
| Tail loss probe is separate RFC | PTO integrated into base spec |

---

## Relevance to dart_quic

1. **Timer precision**: Dart's timer system (`Timer`, `Stopwatch`) must provide at least millisecond granularity for PTO and loss detection.
2. **Per-space tracking**: The implementation needs separate sent-packet lists per encryption level.
3. **Congestion state**: A `CongestionController` class should encapsulate cwnd, ssthresh, bytes_in_flight, and the state machine.
4. **Pluggable algorithms**: The spec encourages experimentation (e.g., CUBIC). The Dart API should allow swapping congestion algorithms.
5. **Pacing**: Consider a token-bucket or leaky-bucket pacer for production quality.
6. **ACK processing**: Must handle ACK ranges efficiently (RFC 9000 Section 19.3) to detect lost packets.

---

## References

- RFC 9002: https://www.rfc-editor.org/rfc/rfc9002
- RFC 9000 Section 13 (Packet Processing): https://www.rfc-editor.org/rfc/rfc9000#section-13
- RFC 6582 (NewReno): https://www.rfc-editor.org/rfc/rfc6582
- RFC 8312 (CUBIC): https://www.rfc-editor.org/rfc/rfc8312
- RFC 6928 (Initial Window): https://www.rfc-editor.org/rfc/rfc6928

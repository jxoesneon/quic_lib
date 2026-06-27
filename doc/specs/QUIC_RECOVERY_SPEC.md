# QUIC Loss Detection and Recovery Specification

**Version**: 1.0-draft  
**Status**: Specification  
**RFC Basis**: RFC 9002  
**Subsystem**: Loss Detection & Congestion Control

---

## 1. Purpose

This document specifies the loss detection and congestion control mechanisms for `dart_quic`: RTT estimation, packet loss detection, probe timeout (PTO), and the NewReno congestion control algorithm.

---

## 2. Architecture

```
┌─────────────────────────────────────────────┐
│            Congestion Controller             │
│  (cwnd, ssthresh, bytes_in_flight, state)   │
├─────────────────────────────────────────────┤
│             Loss Detector                    │
│  (packet tracking, loss declaration, PTO)   │
├─────────────────────────────────────────────┤
│             RTT Estimator                    │
│  (smoothed_rtt, rttvar, min_rtt)           │
├─────────────────────────────────────────────┤
│        ACK Processing / Sent Packets        │
│  (per packet number space)                  │
└─────────────────────────────────────────────┘
```

---

## 3. RTT Estimation (RFC 9002 Section 5)

### 3.1 State Variables

```dart
class RttEstimator {
  Duration? smoothedRtt;
  Duration? rttvar;
  Duration minRtt = Duration.zero;
  Duration latestRtt = Duration.zero;
  
  // From transport parameters
  Duration maxAckDelay;  // peer's max_ack_delay
}
```

### 3.2 On First RTT Sample

```
smoothed_rtt = latest_rtt
rttvar = latest_rtt / 2
min_rtt = latest_rtt
```

### 3.3 On Subsequent Samples

```
min_rtt = min(min_rtt, latest_rtt)
ack_delay = min(reported_ack_delay, max_ack_delay)

if latest_rtt - min_rtt >= ack_delay:
  adjusted_rtt = latest_rtt - ack_delay
else:
  adjusted_rtt = latest_rtt

rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)
smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
```

### 3.4 Constraints

- min_rtt is NEVER smoothed (always the raw minimum).
- ack_delay is NOT subtracted when the sample equals min_rtt (avoids underestimation).
- If no RTT samples exist, PTO uses a default initial RTT of 333ms.

---

## 4. Sent Packet Tracking

### 4.1 Per-Packet Metadata

```dart
class SentPacket {
  final int packetNumber;
  final DateTime timeSent;
  final int sentBytes;        // size in bytes (0 for non-ack-eliciting)
  final bool ackEliciting;    // contains ack-eliciting frames?
  final bool inFlight;        // counts toward bytes_in_flight?
  final List<Frame> frames;   // for potential retransmission
  PacketNumberSpace space;
}
```

### 4.2 Packet Number Spaces

Separate tracking for:
- **Initial**: Packets at Initial encryption level.
- **Handshake**: Packets at Handshake encryption level.
- **Application Data**: Packets at 1-RTT encryption level.

---

## 5. Loss Detection (RFC 9002 Section 6)

### 5.1 On ACK Received

```
function on_ack_received(ack, space, now):
  newly_acked = determine_newly_acked_packets(ack, space)
  if newly_acked is empty:
    return
  
  // Update RTT
  largest_newly_acked = max(newly_acked, by: packet_number)
  if largest_newly_acked.ack_eliciting:
    latest_rtt = now - largest_newly_acked.time_sent
    update_rtt(latest_rtt, ack.ack_delay)
  
  // Process ACKs for congestion control
  for packet in newly_acked:
    on_packet_acked(packet)
  
  // Detect losses
  detect_and_remove_lost_packets(space, now)
  
  // Reset PTO
  reset_pto_timer()
```

### 5.2 Packet Threshold Loss Detection

```
function detect_lost_packets(space, now):
  lost = []
  largest_acked = space.largest_acked_packet
  loss_delay = max(9/8 * max(latest_rtt, smoothed_rtt), kGranularity)
  lost_send_time = now - loss_delay
  
  for packet in space.sent_packets:
    if packet.packet_number > largest_acked:
      continue
    
    // Packet threshold
    if largest_acked - packet.packet_number >= kPacketThreshold:
      lost.append(packet)
    // Time threshold
    elif packet.time_sent <= lost_send_time:
      lost.append(packet)
  
  return lost
```

### 5.3 Constants

```
kPacketThreshold = 3
kTimeThreshold = 9/8  (time-based loss factor)
kGranularity = 1ms    (timer granularity)
```

---

## 6. Probe Timeout (PTO) (RFC 9002 Section 6.2)

### 6.1 Computation

```
function compute_pto(space):
  if smoothed_rtt is None:
    return 2 * kInitialRtt  // 333ms default → 666ms

  pto = smoothed_rtt + max(4 * rttvar, kGranularity)
  
  if space == ApplicationData:
    pto += max_ack_delay
  
  return pto * (2 ^ pto_count)  // exponential backoff
```

### 6.2 On PTO Expiry

```
function on_pto_timeout():
  if has_ack_eliciting_in_flight():
    send_one_or_two_ack_eliciting_packets()  // probes
  else:
    // Client with nothing in flight: send PING
    send_ping()
  
  pto_count += 1
  set_pto_timer()
```

### 6.3 PTO Reset

PTO count resets to 0 when:
- An ACK is received that acknowledges new packets.
- The handshake is confirmed (for handshake PTO).

---

## 7. Congestion Control (RFC 9002 Section 7)

### 7.1 State Variables

```dart
class CongestionController {
  int cwnd;                    // congestion window (bytes)
  int ssthresh = int.maxValue; // slow start threshold
  int bytesInFlight = 0;       // unacknowledged bytes
  DateTime? congestionRecoveryStartTime;
  
  // Constants
  int maxDatagramSize = 1200;
  int get initialWindow => min(10 * maxDatagramSize, max(14720, 2 * maxDatagramSize));
  int get minimumWindow => 2 * maxDatagramSize;
}
```

### 7.2 States

| State | Condition | cwnd Growth |
|-------|-----------|-------------|
| Slow Start | cwnd < ssthresh | += bytes_acked |
| Congestion Avoidance | cwnd >= ssthresh | += max_datagram_size * bytes_acked / cwnd |
| Recovery | After loss event | No growth; cwnd held until recovery ends |

### 7.3 On Packet Acknowledged

```
function on_packet_acked(packet):
  bytes_in_flight -= packet.sent_bytes
  
  if in_congestion_recovery(packet.time_sent):
    return  // don't grow window during recovery
  
  if is_app_limited():
    return  // don't grow window when not fully utilizing it
  
  if cwnd < ssthresh:
    // Slow start
    cwnd += packet.sent_bytes
  else:
    // Congestion avoidance
    cwnd += max_datagram_size * packet.sent_bytes / cwnd
```

### 7.4 On Loss Detected

```
function on_packets_lost(lost_packets):
  for packet in lost_packets:
    bytes_in_flight -= packet.sent_bytes
  
  latest_lost = max(lost_packets, by: time_sent)
  
  if !in_congestion_recovery(latest_lost.time_sent):
    // Enter recovery
    congestion_recovery_start_time = now
    ssthresh = cwnd / 2
    cwnd = max(ssthresh, kMinimumWindow)
```

### 7.5 Persistent Congestion

```
function check_persistent_congestion(lost_packets):
  duration = 3 * (smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay)
  
  // Find two ack-eliciting lost packets with no ACKed packets between them
  // spanning > duration
  if persistent_congestion_detected:
    cwnd = kMinimumWindow
    congestion_recovery_start_time = None
```

### 7.6 ECN Response

```
function on_ecn_ce_increase():
  // Treat same as loss
  if !in_congestion_recovery(now):
    congestion_recovery_start_time = now
    ssthresh = cwnd / 2
    cwnd = max(ssthresh, kMinimumWindow)
```

---

## 8. Pacing (RFC 9002 Section 7.7)

### 8.1 Interval Calculation

```
pacing_interval = smoothed_rtt * max_datagram_size / cwnd
```

### 8.2 Implementation

Use a token bucket that fills at the pacing rate:
- Bucket capacity: `cwnd` (allows burst up to cwnd).
- Fill rate: `cwnd / smoothed_rtt` bytes per second.
- On send: consume `packet_size` tokens. If insufficient tokens, wait.

---

## 9. Anti-Amplification (RFC 9000 Section 8.1)

Before address validation:
```
max_bytes_sendable = 3 * bytes_received_from_peer
```

This limits amplification attacks. After address validation (receiving a handshake message or path response), the limit is removed.

---

## 10. Dart API

```dart
abstract class CongestionControl {
  bool canSend(int packetSize);
  void onPacketSent(SentPacket packet);
  void onPacketAcked(SentPacket packet);
  void onPacketLost(SentPacket packet);
  void onEcnCeCount(int newCeCount);
  Duration get pacingDelay;
}

class NewRenoCongestionControl implements CongestionControl { ... }
class CubicCongestionControl implements CongestionControl { ... }  // future
```

---

## 11. Acceptance Criteria

- [ ] RTT estimation matches expected values for known scenarios.
- [ ] Packet threshold loss detection declares loss at exactly kPacketThreshold gap.
- [ ] Time threshold loss detection uses correct delay calculation.
- [ ] PTO fires at correct time with exponential backoff.
- [ ] Slow start doubles cwnd per RTT.
- [ ] Congestion avoidance grows cwnd by ~1 MSS per RTT.
- [ ] Loss event halves cwnd and sets ssthresh.
- [ ] Persistent congestion resets cwnd to minimum.
- [ ] ECN CE count increase triggers congestion response.
- [ ] Anti-amplification limits are enforced.
- [ ] Pacing rate matches theoretical calculation.

---

## 12. Security Considerations

- **ACK manipulation**: A compromised peer could send false ACKs to inflate cwnd. The protocol relies on packet protection to prevent this.
- **Amplification**: Anti-amplification limits (3x) MUST be enforced before address validation.
- **PTO flooding**: Implementations should limit PTO probe rate to prevent self-inflicted amplification.

---

## 13. Dependencies

- RTT samples from ACK processing.
- Wire codec (ACK frame parsing).
- Packet protection (for reliable ACK delivery).
- Timer system (Dart `Timer` for PTO scheduling).

---

## 14. Testing Strategy

- Simulation: Drive loss detector with synthetic ACK sequences.
- Congestion control: Verify cwnd evolution under various loss patterns.
- PTO: Verify timer fires at correct intervals with backoff.
- Persistent congestion: Verify detection with various packet patterns.
- Interop: Verify throughput against quic-go under controlled loss rates.

---

## References

- RFC 9002: https://www.rfc-editor.org/rfc/rfc9002
- RFC 6582 (NewReno): https://www.rfc-editor.org/rfc/rfc6582
- RFC 8312 (CUBIC): https://www.rfc-editor.org/rfc/rfc8312
- RFC 3449 (TCP Performance over Paths with Varying Characteristics): https://www.rfc-editor.org/rfc/rfc3449

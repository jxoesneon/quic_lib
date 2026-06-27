---
title: "CUBIC Congestion Control Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Unknown"
rfc_basis: []
dependencies:
  - "DART_API_SPEC.md"
  - "QUIC_RECOVERY_SPEC.md"
---

# CUBIC Congestion Control Specification


## 1. Purpose

High-BDP networks demand congestion controllers that scale beyond TCP-Reno linear window growth. CUBIC provides a cubic-function window evolution that is TCP-friendly for small windows yet aggressive for large ones, enabling dart_quic to perform competitively on long-fat links. This spec defines the pluggable CUBIC implementation so that downstream consumers such as dart_ipfs can saturate P2P links without rewriting the recovery subsystem.

## 2. Detailed Specification
### 2.1 Relationship to QUIC Recovery (RFC 9002)

RFC 9002 defines the loss detection, probe timeout (PTO), persistent congestion, and ECN handling for QUIC. It specifies a default congestion controller similar to TCP NewReno but explicitly allows other algorithms.

CUBIC plugs into the same recovery hooks as NewReno:

| Recovery Event | CUBIC Action |
|----------------|--------------|
| Packet ACKed | Update `bytes_in_flight`, grow `cwnd` if not in recovery/app-limited |
| Packet lost | Reduce `cwnd` via multiplicative decrease (`beta_cubic`) |
| ECN CE count increase | Treat same as loss |
| Persistent congestion | Reset `cwnd` to `kMinimumWindow` |
| PTO | No change to `cwnd` (send probe) |

The loss detector, RTT estimator, and persistent congestion logic remain unchanged from [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md). Only the congestion window evolution differs.

---


### 2.2 CUBIC Constants and Conventions


#### 2.2.1 Constants

| Constant | Symbol | Value | Description |
|----------|--------|-------|-------------|
| `kCubicC` | C | 0.4 | CUBIC scaling factor |
| `kCubicBeta` | `beta_cubic` | 0.7 | Multiplicative decrease factor |
| `kMaxDatagramSize` | MSS | 1200 (configurable) | Segment size used for window calculations |
| `kInitialWindow` | | `min(10 * maxDatagramSize, max(14720, 2 * maxDatagramSize))` | Initial `cwnd` (from RFC 9002) |
| `kMinimumWindow` | | `2 * maxDatagramSize` | Minimum `cwnd` after loss (from RFC 9002) |


#### 2.2.2 Conventions

All CUBIC window calculations are performed in units of **segments** (MSS-sized units), not bytes. Public `cwnd` values are stored in bytes but converted to segments for the CUBIC function:

```dart
int cwndInSegments() => cwnd ~/ maxDatagramSize;
```

All time values are measured as `Duration` from `DateTime` timestamps. The CUBIC elapsed time `t` is the duration since the last congestion window reduction (the start of the current "epoch").

---


### 2.3 State Variables

CUBIC-specific state (in addition to the base `CongestionControl` fields defined in [DART_API_SPEC.md](DART_API_SPEC.md) Section 5.5):

```dart
class CubicCongestionControl implements CongestionControl {
  // Inherited from CongestionControl: cwnd, ssthresh, bytesInFlight, congestionRecoveryStartTime

  // CUBIC-specific
  int maxDatagramSize;         // MSS
  int W_max;                   // cwnd (in segments) just before last reduction
  int lastW_max;               // W_max from the previous loss epoch (fast convergence)
  DateTime? epochStart;        // time of last cwnd reduction
  double K;                    // time to increase W_cubic to W_max (seconds)
  Duration smoothedRtt;        // shared from RTT estimator
}
```

---


### 2.4 Window Max (W_max) and K Calculation


#### 2.4.1 W_max

`W_max` is the congestion window size (in segments) at the moment just before the last multiplicative decrease.

On a congestion event:

```dart
W_max = cwnd ~/ maxDatagramSize;  // in segments
```


#### 2.4.2 K Calculation

`K` is the time period required for the CUBIC function to increase from `beta_cubic * W_max` back to `W_max`.

```dart
K = cubic_root((W_max * (1 - beta_cubic)) / C)
```

In Dart-like pseudocode:

```dart
double K = pow((W_max * (1 - kCubicBeta)) / kCubicC, 1.0 / 3.0);
```

`K` is stored in seconds. For timestamp arithmetic it is converted to a `Duration`.

---


### 2.5 CUBIC Window Growth Function


#### 2.5.1 Definition

The CUBIC window growth function is defined as:

```dart
W_cubic(t) = C * (t - K)^3 + W_max
```

where:

- `t` is the elapsed time since the last window reduction (`Duration` converted to seconds).
- `K` is computed from `W_max` and `beta_cubic`.
- `C` is the CUBIC constant.


#### 2.5.2 Regions

| Region | Condition | Shape | Growth Behavior |
|--------|-----------|-------|-----------------|
| Concave | `0 <= t < K` | `W_cubic` increases at a decreasing rate | Aggressive ramp-up after loss |
| Inflection | `t == K` | Slope is zero | Window is `W_max` |
| Convex | `t > K` | `W_cubic` increases at an increasing rate | Slow, steady growth |


#### 2.5.3 TCP-Friendly Estimate

CUBIC defines a TCP-friendly estimate to avoid being more aggressive than Reno for small windows:

```dart
W_est(t) = W_max * beta_cubic + (3 * (1 - beta_cubic) / (1 + beta_cubic)) * (t / smoothedRtt)
```

where `smoothedRtt` is expressed in seconds (or the same unit as `t`).

The target window is:

```dart
target = max(W_cubic(t), W_est(t))
```

This ensures that when `cwnd` is small, CUBIC does not behave more aggressively than standard TCP.

---


### 2.6 Congestion Avoidance Update


#### 2.6.1 On Packet Acknowledged

When a packet is newly acknowledged and the controller is not in congestion recovery or app-limited:

1. Update `bytesInFlight`.
2. If `cwnd < ssthresh`, perform slow start (see Section 10).
3. Otherwise, compute `t = now - epochStart`.
4. Compute `W_cubic(t)` and `W_est(t)`.
5. Set `target = max(W_cubic(t), W_est(t))`.
6. Convert `target` to bytes: `targetBytes = target * maxDatagramSize`.
7. Update `cwnd` toward `targetBytes`:

```dart
cwnd += ((targetBytes - cwnd) * bytesAcked) ~/ cwnd;
```

This ensures `cwnd` converges to the CUBIC target over the course of the current RTT.


#### 2.6.2 On RTT Update

CUBIC uses the smoothed RTT from the shared RTT estimator. The `smoothedRtt` value is updated by the recovery subsystem; CUBIC reads it but does not modify it. When `smoothedRtt` is unavailable, CUBIC uses the initial RTT of 333 ms.

---


### 2.7 Fast Convergence

Fast Convergence (RFC 8312 Section 4.6) improves convergence when the available bandwidth has decreased.

On a congestion event, before the multiplicative decrease:

```dart
if (W_max < lastW_max) {
  W_max = (W_max * (1 + beta_cubic) / 2).toInt();
}
```

This reduces the next `W_max` and therefore `K`, allowing CUBIC to converge more quickly to a lower stable rate.

State required:

```dart
int lastW_max = 0;
```

After the reduction, set `lastW_max = W_max` (the original value before any fast-convergence adjustment).

---


### 2.8 Multiplicative Decrease (Beta)

On a loss detection or ECN CE event, if not already in congestion recovery:

1. Record `W_max = cwnd ~/ maxDatagramSize`.
2. Apply fast convergence (Section 8).
3. Reduce `cwnd`:

```dart
ssthresh = max((cwnd * beta_cubic).toInt(), kMinimumWindow);
cwnd = ssthresh;
```

4. Record `epochStart = now`.
5. Compute `K` from the adjusted `W_max`.
6. Set `congestionRecoveryStartTime = now` (per RFC 9002).

If already in congestion recovery, no further reduction occurs.

---


### 2.9 Slow Start

CUBIC uses the standard TCP slow start algorithm defined in RFC 9002:

```dart
if (cwnd < ssthresh) {
  cwnd += bytesAcked;
}
```

An implementation MAY optionally use Hystart (RFC 8312 Appendix B) to exit slow start early, but this is not required for compliance.

---


### 2.10 Interface with the CongestionControl Abstraction


#### 2.10.1 Interface Requirements

CUBIC implements the `CongestionControl` interface defined in [DART_API_SPEC.md](DART_API_SPEC.md) Section 5.5. Because CUBIC is time-dependent, the interface passes the current timestamp to event handlers. The interface includes `canSend`, `onPacketSent`, `onPacketAcked`, `onPacketLost`, `onEcnCeCount`, `onRttSample`, and `pacingDelay`.


#### 2.10.2 Method Mapping

| Method | CUBIC Behavior |
|--------|----------------|
| `canSend` | `bytesInFlight + packetSize <= cwnd` |
| `onPacketSent` | `bytesInFlight += packet.sent_bytes` |
| `onPacketAcked` | `bytesInFlight -= packet.sent_bytes`; run Section 7 update |
| `onPacketLost` | `bytesInFlight -= packet.sent_bytes`; run Section 9 decrease |
| `onEcnCeCount` | Same as loss if CE count increased |
| `onRttSample` | Update local `smoothedRtt` reference |
| `pacingDelay` | `smoothedRtt * maxDatagramSize / cwnd` |

---


### 2.11 Integration with the Existing NewReno Implementation

The `QuicConfiguration.congestionAlgorithm` field selects the implementation:

```dart
enum CongestionAlgorithm {
  newReno,
  cubic,
}
```

The connection factory constructs the matching `CongestionControl` implementation at startup. Both implementations share:

- The same `CongestionControl` interface.
- The same `RttEstimator`.
- The same `LossDetector`.
- The same initial window (`kInitialWindow`) and minimum window (`kMinimumWindow`).
- The same persistent congestion and ECN response rules.
- The same pacing subsystem.

A connection MUST use one algorithm for its lifetime; runtime switching is not required. Configuration changes via `copyWith` apply only to new connections.


#### 2.11.1 Switching Algorithm

To switch from NewReno to CUBIC, set:

```dart
const config = QuicConfiguration(
  congestionAlgorithm: CongestionAlgorithm.cubic,
);
```

Both algorithms are initialized with the same `cwnd`, `ssthresh`, `bytesInFlight`, and `maxDatagramSize`. No state is carried over when switching algorithms for a new connection.

---


### 2.12 Pacing

CUBIC relies on pacing to avoid burst-induced losses. The pacing interval is:

```dart
Duration pacingDelay = smoothedRtt * maxDatagramSize / cwnd;
```

When `cwnd` is small or `smoothedRtt` is unknown, the controller may return `Duration.zero` to allow immediate sending.

The token-bucket pacer is shared between NewReno and CUBIC and is specified in [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md) Section 8.

---


### 2.13 Persistent Congestion and ECN

Persistent congestion and ECN handling follow [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md) exactly:

- Persistent congestion resets `cwnd` to `kMinimumWindow` and clears `congestionRecoveryStartTime` and `epochStart`.
- An ECN CE count increase triggers the same multiplicative decrease as a loss event.
- PTO expiry does not reduce `cwnd`.

---


### 2.14 Test Cases


#### 2.14.1 Unit Tests

1. **K calculation**: Given `W_max = 100` segments, `beta = 0.7`, `C = 0.4`, compute `K` and verify `K = cbrt(100 * 0.3 / 0.4)`.
2. **Concave/convex region**: Evaluate `W_cubic(t)` at `t = 0`, `t = K`, and `t = 2K`; verify `W_cubic(0) = beta * W_max`, `W_cubic(K) = W_max`, and `W_cubic(2K) > W_max`.
3. **Loss decrease**: `cwnd = 100 * MSS`; after loss, `cwnd = 70 * MSS`.
4. **Fast convergence**: After two losses where the second `W_max` is lower than the first, verify the adjusted `W_max` is lower than the original.
5. **TCP-friendly region**: With small `cwnd` and long `t`, verify `target = W_est(t)` when `W_est(t) > W_cubic(t)`.
6. **Switching**: Create two controllers with the same loss/ACK sequences; verify `cwnd` trajectories differ between NewReno and CUBIC.


#### 2.14.2 Simulation Tests

1. **Steady-state throughput**: Simulate a 100 ms RTT path with 1% random loss; verify CUBIC achieves higher throughput than NewReno over 10 seconds.
2. **Fairness**: Run two CUBIC flows and two NewReno flows over the same bottleneck; verify flow rates converge within 20% of each other.


#### 2.14.3 Integration Tests

1. **Interop with quic-go**: Establish a connection using `CongestionAlgorithm.cubic` and transfer data; verify no stalls under 1% loss.
2. **Configuration**: Verify `QuicConfiguration.copyWith(congestionAlgorithm: CongestionAlgorithm.cubic)` produces a CUBIC-backed connection.

---



## 3. Acceptance Criteria

- [ ] CUBIC constants match RFC 8312 defaults: `C = 0.4`, `beta_cubic = 0.7`.
- [ ] `K` calculation is correct for sample `W_max` values.
- [ ] `W_cubic(t)` is concave for `0 <= t < K` and convex for `t > K`.
- [ ] TCP-friendly estimate `W_est(t)` keeps the target window at least as large as the equivalent TCP Reno window when `cwnd` is small.
- [ ] After a single loss event, `cwnd` is reduced to `beta_cubic * W_max` (subject to `kMinimumWindow`).
- [ ] Fast convergence reduces `W_max` when the current `W_max` is less than `lastW_max`.
- [ ] Slow start doubles `cwnd` per RTT until `ssthresh`.
- [ ] Congestion avoidance grows `cwnd` according to the CUBIC function, not linearly.
- [ ] Pacing delay equals `smoothedRtt * maxDatagramSize / cwnd`.
- [ ] ECN CE count increase triggers the same reduction as loss.
- [ ] Persistent congestion resets `cwnd` to `kMinimumWindow`.
- [ ] Switching `congestionAlgorithm` between `newReno` and `cubic` produces algorithm-appropriate window evolution.
- [ ] CUBIC and NewReno share identical bytes-in-flight accounting.

---





## 4. Security Considerations

- **ACK manipulation**: Same as NewReno; packet protection prevents forged ACKs.
- **Pacing granularity**: Low-precision timers may cause bursts. Implementations SHOULD use a token-bucket pacer.
- **Time precision**: `DateTime` resolution is platform-dependent. Tests must account for millisecond rounding.
- **Fast convergence safety**: Fast convergence MUST NOT reduce `cwnd` below `kMinimumWindow`.

---





## 5. Dependencies

- [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md): Loss detection, RTT estimation, persistent congestion, and NewReno specification.
- [DART_API_SPEC.md](DART_API_SPEC.md): `QuicConfiguration`, `CongestionAlgorithm`, and the `CongestionControl` interface.
- RFC 8312: CUBIC algorithm.
- RFC 9002: QUIC recovery framework.

---















## Used By

- [DART_API_SPEC.md](DART_API_SPEC.md) — References CongestionAlgorithm.cubic and the CongestionControl interface.
- [QUIC_RECOVERY_SPEC.md](QUIC_RECOVERY_SPEC.md) — Cites CUBIC as the optional pluggable congestion controller alongside NewReno.
## 6. References

- RFC 8312: CUBIC for Fast Long-Distance Networks: https://www.rfc-editor.org/rfc/rfc8312
- RFC 9002: QUIC Loss Detection and Congestion Control: https://www.rfc-editor.org/rfc/rfc9002
- RFC 6582: The NewReno Modification to TCP's Fast Recovery Algorithm: https://www.rfc-editor.org/rfc/rfc6582
- RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport: https://www.rfc-editor.org/rfc/rfc9000
- RFC 8312 Appendix B: Hystart (optional).
---
title: "Performance Benchmarking Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Unknown"
rfc_basis: []
dependencies:
  - "ROADMAP.md"
  - "TESTING_SPEC.md"
---

# Performance Benchmarking Specification


## 1. Purpose

Performance claims without reproducible measurements are indistinguishable from wishful thinking. Without a benchmarking spec, regressions will go unnoticed and users will have no basis for comparing dart_quic against other stacks. This document defines the methodology, baselines, and CI integration needed to keep the implementation honest as it evolves.

## 2. Detailed Specification
### 2.1 Benchmark Framework


#### 2.1.1 Primary Framework

Use [`package:benchmark`](https://pub.dev/packages/benchmark) as the primary harness for **micro-benchmarks**:

- Wire-format codecs (varint, frame encoding/decoding).
- Packet protection primitives (AES-128-GCM, ChaCha20-Poly1305, header protection).
- QPACK header compression/decompression.
- Stream state transitions and reassembly buffer operations.

`package:benchmark` provides warmup, multiple iterations, outlier reporting, and statistical summaries that align with the methodology in Section 3.


#### 2.1.2 Custom Harness for Macro-Benchmarks

Use a **custom Dart harness** for end-to-end measurements that require coordinated client and server instances:

- Handshake latency (loopback and emulated RTT).
- Single-stream and multi-stream throughput over UDP loopback or a controlled network emulator.
- HTTP/3 request/response throughput.
- RTT estimation accuracy under synthetic delay.

The custom harness MUST:
- Report wall-clock time using `Stopwatch` with microsecond precision.
- Run the client and server in separate isolates (`Isolate.spawn`) to avoid event-loop interference.
- Bind to loopback interfaces (`127.0.0.1` / `::1`) for local benchmarks.
- Optionally integrate with `tc`/`netem` or a lightweight in-process simulator for latency, loss, and jitter.


#### 2.1.3 Directory Layout

```
benchmark/
├── micro/
│   ├── varint_benchmark.dart
│   ├── packet_encrypt_benchmark.dart
│   ├── qpack_benchmark.dart
│   └── stream_reassembly_benchmark.dart
└── macro/
    ├── handshake_latency_benchmark.dart
    ├── throughput_single_stream_benchmark.dart
    ├── throughput_multi_stream_benchmark.dart
    └── rtt_estimation_benchmark.dart
```

---


### 2.2 Measurement Methodology


#### 2.2.1 Reference Hardware

All baseline targets in this document are defined for one of the following reference configurations:

| Configuration | CPU | RAM | OS | Network |
|-------------|-----|-----|----|---------|
| **Apple Silicon** | Apple M1 (or newer) | 16 GB | macOS latest | Loopback / 1 Gbps Ethernet |
| **Modern x86 Desktop** | AMD Ryzen 5 5600X / Intel Core i5-12400 (or equivalent) | 16 GB | Windows 11 / Ubuntu 22.04 LTS | Loopback / 1 Gbps Ethernet |

Benchmarks SHOULD also report the actual hardware used when publishing results.


#### 2.2.2 Environmental Controls

Before each benchmark run:

- Disable CPU frequency scaling (e.g., `performance` governor on Linux, `sudo pmset -c` on macOS, `High performance` power plan on Windows).
- Close non-essential applications and background services.
- Run benchmarks on wall power (not battery).
- Pin the Dart process to a single core when measuring pure CPU-bound micro-benchmarks (optional but recommended for variance reduction).
- Use `dart run --release` or compiled AOT (`dart compile exe`) for all reported numbers.
- Warm up the JIT/AOT runtime before capturing measurements.


#### 2.2.3 Warmup

Every benchmark MUST perform a warmup phase sufficient to stabilize the Dart VM, caches, and OS network buffers:

| Benchmark Type | Warmup Requirement |
|----------------|-------------------|
| Micro-benchmarks | At least 1000 iterations or 2 seconds, whichever is longer. |
| Macro-benchmarks | At least 100 handshake/transfer iterations or 5 seconds, whichever is longer. |
| Network-bound benchmarks | Pre-fill network buffers with at least 10 MB of transfer before measurement. |


#### 2.2.4 Iterations and Duration

| Benchmark Type | Minimum Iterations | Minimum Measurement Time | Runs |
|----------------|--------------------|--------------------------|------|
| Micro-benchmarks | 10,000 iterations | 5 seconds | 10 runs |
| Macro-benchmarks | 100 iterations | 30 seconds | 10 runs |
| Crypto throughput | 50,000 iterations | 10 seconds | 10 runs |
| RTT estimation | 1,000 RTT samples | 60 seconds | 5 runs |


#### 2.2.5 Statistical Handling

For each benchmark, collect all raw samples and report:

- **Mean** (arithmetic average)
- **Median** (50th percentile)
- **p95** and **p99** (tail latency)
- **Standard deviation** and **relative standard deviation (RSD)**
- **Minimum** and **maximum** after outlier removal

Outlier removal:
- Discard the lowest and highest 2% of samples before computing trimmed statistics.
- If a run contains more than 5% outliers beyond 3 standard deviations from the median, flag the run as unstable and repeat it.

Use the **median** of the trimmed distribution as the primary comparison metric. Report confidence intervals where the benchmark framework supports them.


#### 2.2.6 Units and Reporting Format

| Metric | Unit | Example |
|--------|------|---------|
| Handshake latency | milliseconds (ms) | 12.5 ms |
| Throughput | MB/s or Gbps | 110 MB/s |
| Crypto throughput | packets/second | 210,000 pkt/s |
| Codec throughput | operations/second | 12,000,000 ops/s |
| RTT error | percentage (%) | 2.3% |
| Memory usage | MB per 1,000 connections | 45 MB |

Publish results in JSON format under `benchmark/results/`:

```json
{
  "benchmark": "handshake_latency_local",
  "commit": "a1b2c3d",
  "timestamp": "2026-01-15T10:00:00Z",
  "hardware": "Apple M1, 16 GB",
  "dart_sdk": "3.5.0",
  "samples": 1000,
  "median_ms": 12.5,
  "p95_ms": 18.2,
  "p99_ms": 22.1,
  "mean_ms": 13.1,
  "stddev_ms": 2.4
}
```

---


### 2.3 Baseline Targets (Reference Hardware)


#### 2.3.1 Handshake Latency

| Scenario | Target | Measurement |
|----------|--------|-------------|
| 1-RTT handshake, local loopback, RSA-2048 or P-256 certificate | **< 50 ms** (median) | Time from first client Initial to handshake-confirmed. |
| 0-RTT resumed handshake, local loopback | **< 25 ms** (median) | Time from first client Initial to sending 0-RTT data. |
| Tail latency (p99) | **< 2x median** | For local loopback with no packet loss. |

The latency target assumes a single client and single server on the same host with sub-millisecond loopback RTT.


#### 2.3.2 Single-Stream Throughput

| Scenario | Target | Measurement |
|----------|--------|-------------|
| One bidirectional stream over a 1 Gbps emulated network | **> 100 MB/s** (≈ 800 Mbps) | Application-level throughput measured at the receiver. |
| Local loopback (no external network limit) | **> 300 MB/s** | Demonstrates protocol and implementation overhead. |
| Measurement duration | ≥ 30 seconds | Report steady-state throughput after slow-start. |

Use a payload size of at least 1 MB per stream and disable artificial flow-control limits for the benchmark (or set them large enough to never block).


#### 2.3.3 Multi-Stream Throughput

| Scenario | Target | Measurement |
|----------|--------|-------------|
| 100 concurrent streams over 1 Gbps network | **≥ 95% of single-stream throughput** | Aggregate throughput across all streams. |
| 1,000 concurrent streams | **≥ 90% of single-stream throughput** | Aggregate throughput across all streams. |
| Per-stream overhead | **< 5%** throughput loss per order-of-magnitude increase in stream count. |


#### 2.3.4 AES-128-GCM Packet Encryption

| Scenario | Target | Measurement |
|----------|--------|-------------|
| Encrypt + protect 1,200-byte packets | **> 200,000 packets/second** | Includes AEAD seal and header protection. |
| Decrypt + unprotect 1,200-byte packets | **> 200,000 packets/second** | Includes AEAD open and header removal. |
| ChaCha20-Poly1305 fallback | **> 150,000 packets/second** | For platforms without AES-NI. |

The packet size targets the default QUIC maximum datagram size (≈ 1,200 bytes). Benchmarks SHOULD also report 100-byte and 1,500-byte packet sizes.


#### 2.3.5 RTT Estimation Accuracy

| Scenario | Target | Measurement |
|----------|--------|-------------|
| Synthetic RTT 10 ms | **< 5% error** | `|estimated_rtt - synthetic_rtt| / synthetic_rtt`. |
| Synthetic RTT 100 ms | **< 3% error** | After convergence (≥ 100 samples). |
| Synthetic RTT 200 ms | **< 3% error** | After convergence. |
| Variance under jitter (± 10% RTT) | **< 10% error** | Median of `smoothed_rtt` over 1,000 samples. |


#### 2.3.6 Additional Micro-Benchmarks

| Benchmark | Target | Notes |
|-----------|--------|-------|
| Varint encode/decode | > 10,000,000 ops/s | All four encoding sizes. |
| QPACK encoder/decoder | > 100,000 headers/s | Mix of static and dynamic table entries. |
| Frame encode/decode | > 1,000,000 frames/s | All frame types. |
| Connection state creation | < 100 µs | No I/O. |

---


### 2.4 Regression Threshold Definitions

A regression is defined as a statistically significant increase in latency or decrease in throughput relative to the established baseline on reference hardware.


#### 2.4.1 Latency Regressions

| Metric | Investigation Threshold | Block Threshold |
|--------|--------------------------|-----------------|
| Handshake latency (1-RTT) | +5% | +10% |
| Handshake latency (0-RTT) | +5% | +10% |
| RTT estimation error | +20% | +50% |
| Tail latency (p99) | +10% | +25% |


#### 2.4.2 Throughput Regressions

| Metric | Investigation Threshold | Block Threshold |
|--------|--------------------------|-----------------|
| Single-stream throughput | -10% | -15% |
| Multi-stream throughput | -10% | -15% |
| Crypto throughput | -10% | -20% |
| Codec throughput | -10% | -20% |


#### 2.4.3 Memory Regressions

| Metric | Investigation Threshold | Block Threshold |
|--------|--------------------------|-----------------|
| Memory per connection | +10% | +20% |
| Allocations per packet | +10% | +20% |


#### 2.4.4 Regression Response

- **Investigation threshold**: Open a tracking issue and re-run the benchmark on the same reference hardware to confirm.
- **Block threshold**: Prevent merging the associated PR until the regression is understood, justified, or fixed. A maintainer MAY override with a documented exception.
- Statistical significance: require at least 3 consecutive benchmark runs above the threshold before declaring a regression.

---


### 2.5 CI Integration Plan


#### 2.5.1 Benchmark Job Schedule

| Job | Trigger | Runner | Duration | Dart Mode |
|-----|---------|--------|----------|-----------|
| Micro-benchmarks | Every PR (if code changes benchmarks) | Standard CI runner | < 5 min | AOT or VM `--release` |
| Macro-benchmarks | Weekly + release candidates | Reference hardware runner | < 20 min | AOT or VM `--release` |
| Full benchmark suite | Nightly on `main` | Reference hardware runner | < 30 min | AOT or VM `--release` |
| Regression check | On PRs tagged `perf-sensitive` | Reference hardware runner | < 20 min | AOT or VM `--release` |


#### 2.5.2 Reference Hardware Runner

Maintain a dedicated CI runner (self-hosted or cloud instance) matching the reference hardware profile. Document the exact CPU, OS, Dart SDK version, and network configuration in the runner setup guide.


#### 2.5.3 Baseline Storage and Comparison

- Store official baseline results in `benchmark/baselines/reference_hardware.json`.
- On each scheduled run, write results to `benchmark/results/<benchmark>_<timestamp>.json`.
- Compare the new median against the stored baseline using the thresholds in Section 5.
- Upload results as CI artifacts and, if available, publish them to a benchmark dashboard.


#### 2.5.4 CI Script Requirements

The CI benchmark job MUST:
1. Check out the baseline file and the previous nightly result.
2. Warm up and run each benchmark according to Section 3.
3. Emit a JSON report for each benchmark.
4. Compare against baselines and fail the job if a block threshold is exceeded.
5. Comment the comparison summary on the PR (if triggered by a PR).

Example failure condition (pseudocode):

```yaml
- name: Compare benchmarks
  run: dart benchmark/compare.dart --baseline benchmark/baselines/reference_hardware.json --results benchmark/results/
```


#### 2.5.5 Reporting and Alerts

- Slack / email alert on nightly benchmark failure or regression detection.
- PR comment with a table of benchmark changes when `perf-sensitive` is applied.
- Monthly performance review issue summarizing trends and drift.

---



## 3. Acceptance Criteria

- [ ] At least one reference hardware configuration is documented and available for benchmarking.
- [ ] Micro-benchmark harness (`package:benchmark`) is wired for packet encryption, varint, frame, and QPACK benchmarks.
- [ ] Macro-benchmark harness is wired for handshake latency, single-stream throughput, multi-stream throughput, and RTT estimation.
- [ ] Baseline results for reference hardware are recorded in `benchmark/baselines/reference_hardware.json`.
- [ ] CI job runs the benchmark suite on the reference hardware at least weekly and on every release candidate.
- [ ] Regression thresholds are enforced by CI and documented in this spec.
- [ ] Three consecutive stable runs meet all baseline targets before the specification is considered satisfied.
- [ ] Benchmark documentation is added to the developer guide explaining how to run benchmarks locally.

---





## 4. Security Considerations

- Benchmarks MUST use self-signed certificates or a dedicated test CA; never use production certificates.
- Macro-benchmarks MUST bind only to loopback interfaces unless run in an isolated network environment.
- Do not expose benchmark servers on public ports.
- Avoid logging key material or payload content in benchmark outputs.

---





## 5. Dependencies

- `package:benchmark` — micro-benchmark harness.
- `package:test` — macro-benchmark assertions and integration.
- `tc` / `netem` or a Dart-based network simulator — emulated network conditions.
- CI runner matching the reference hardware profile.

---















## Used By

No direct spec dependents. Referenced from architecture documents.
## 6. References

- `TESTING_SPEC.md` — overall testing strategy and links to this document.
- `FUZZING_SPEC.md` — companion specification for fuzz testing.
- `QUIC_RECOVERY_SPEC.md` — RTT estimation and congestion control targets.
- `QUIC_CRYPTO_SPEC.md` — cryptographic primitives and packet protection.
- `package:benchmark`: https://pub.dev/packages/benchmark
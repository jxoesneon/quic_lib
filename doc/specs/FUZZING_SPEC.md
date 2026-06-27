---
title: "Fuzzing Specification"
category: spec
version: "1.0-draft"
status: "Specification"
subsystem: "Fuzz Testing"
rfc_basis: []
dependencies:
  - "TESTING_SPEC.md"
---

# Fuzzing Specification


## 1. Purpose

Network parsers that consume untrusted input are the most common source of security vulnerabilities in transport stacks. Structured fuzzing gives dart_quic a systematic way to discover crashes, hangs, and correctness violations before they reach production, reducing the risk of zero-days in downstream applications like dart_ipfs.

## 2. Detailed Specification
### 2.1 Fuzzing Targets

The following components MUST be fuzzed because they process untrusted network input.


#### 2.1.1 Packet Parser

| Target | Input | Invariants |
|--------|-------|------------|
| Long header parser | Random bytes with valid/invalid version, DCID, SCID lengths | No crash; invalid forms return a structured error. |
| Short header parser | Random bytes with varying DCID lengths | No crash; invalid lengths return a structured error. |
| Coalesced packet splitter | Multiple packets concatenated with random boundaries | No crash; each sub-packet is parsed or rejected independently. |
| Version negotiation parser | Random version lists | No crash; unknown versions are ignored. |


#### 2.1.2 Frame Parser

| Target | Input | Invariants |
|--------|-------|------------|
| Frame type decoder | Random first byte + payload | No crash; unsupported types are rejected. |
| Per-frame payload parsers | STREAM, ACK, MAX_DATA, MAX_STREAM_DATA, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE, etc. | No crash; all length fields validated before memory allocation. |
| Variable-length integer decoder | Random 1–8 byte sequences | No crash; overflow returns an error. |


#### 2.1.3 Cryptographic Components

| Target | Input | Invariants |
|--------|-------|------------|
| Initial secret derivation | Random destination connection IDs | No crash; deterministic output for valid IDs. |
| AEAD decrypt | Random ciphertext, random nonces, random AAD | No crash; decryption failures return an error, never throw. |
| Header protection remove | Random bytes with valid/invalid sample offsets | No crash; out-of-range samples return an error. |
| Retry integrity tag verify | Random Retry packets | No crash; invalid tags return an error. |
| Transport parameter parser | Random TLV sequences | No crash; malformed parameters close connection with `TRANSPORT_PARAMETER_ERROR`. |


#### 2.1.4 Stream State Machine and Reassembly

| Target | Input | Invariants |
|--------|-------|------------|
| Send stream state machine | Random sequences of SEND / FIN / RESET_STREAM / STOP_SENDING | No crash; only valid state transitions accepted. |
| Receive stream state machine | Random sequences of receive / FIN / RESET_STREAM | No crash; only valid state transitions accepted. |
| Reassembly buffer | Random (offset, length, data) tuples, including overlaps and duplicates | No crash; total buffered bytes never exceeds flow-control limit. |
| Flow-control limit enforcement | Random MAX_DATA / MAX_STREAM_DATA updates | No crash; sender blocks when limit is reached. |


#### 2.1.5 HTTP/3 Frames

| Target | Input | Invariants |
|--------|-------|------------|
| SETTINGS frame parser | Random settings identifiers and values | No crash; unknown settings ignored (unless known-to-be-unsupported). |
| HEADERS frame parser | Random encoded field sections | No crash; malformed headers return `H3_HEADERS_BLOCKED` or `H3_GENERAL_PROTOCOL_ERROR`. |
| DATA / GOAWAY / PUSH_PROMISE / PRIORITY_UPDATE parsers | Random payloads | No crash; stream IDs validated. |
| Capsule protocol parser | Random capsule types and lengths | No crash; unknown capsules skipped. |


#### 2.1.6 QPACK

| Target | Input | Invariants |
|--------|-------|------------|
| Encoder instruction parser | Random encoder stream instructions | No crash; invalid dynamic table references rejected. |
| Decoder instruction parser | Random decoder stream instructions | No crash; invalid references rejected. |
| Header block decoder | Random header blocks with mixed literal/indexed refs | No crash; never emits more than `SETTINGS_MAX_FIELD_SECTION_SIZE`. |
| Dynamic table insertions | Random inserts and capacity changes | No crash; capacity never exceeds declared limit. |

---


### 2.2 Fuzzing Framework


#### 2.2.1 Dart-Specific Approach

Dart does not have a mature, general-purpose integration with AFL or libFuzzer for pure Dart code. Therefore, the primary fuzzing approach for `dart_quic` is **structured fuzzing implemented in Dart** using the existing test framework.

Each fuzz target is a Dart program or test that:
1. Accepts a random seed (or reads from a corpus file).
2. Generates a structured, semantically aware input with controlled randomness.
3. Feeds the input to the parser or state machine under test.
4. Asserts that no crash, uncaught exception, or invariant violation occurs.
5. Logs the seed and input bytes if a failure is found for reproducibility.

Use `package:test` or standalone Dart scripts for the harness. Randomness is provided by `Random.secure()` or a deterministic PRNG seeded from the command line for reproducible regression tests.


#### 2.2.2 Structured Fuzzing Generators

Implement targeted generators per component:

- **Raw bytes generator**: uniform, biased boundary, and printable variants.
- **QUIC packet generator**: builds long/short headers, coalesces valid and invalid packets, and mutates lengths.
- **Frame generator**: emits valid frame headers with random payloads, then mutates length and type fields.
- **QPACK generator**: produces valid and invalid encoder/decoder instructions and header blocks.
- **State-machine generator**: sequences of valid/invalid API calls weighted toward transition boundaries.
- **Crypto generator**: random CIDs, ciphertexts, nonces, and transport parameter TLV sequences.

Generators SHOULD be aware of protocol boundaries to maximize coverage of error paths without producing only trivially invalid inputs.


#### 2.2.3 Coverage Guidance

Because pure Dart fuzzing lacks native coverage feedback, supplement with:

- **Dart coverage collection** (`dart test --coverage`) run periodically on the fuzz corpus to confirm error paths are exercised.
- **Manual coverage review**: ensure each fuzz target has at least one seed that triggers every documented error return path.
- **Targeted mutators**: bias mutations toward length fields, boundary values, and type discriminators that historically expose parser bugs.


#### 2.2.4 Native Library Integration

If `dart_quic` binds to a native cryptographic or transport library (e.g., via `dart:ffi`):

- Provide a thin C/C++ shim that exposes the same entry points to AFL++ or libFuzzer.
- Run the native fuzzer on the shim independently from the Dart fuzzer.
- Reproduce native crashes through the Dart bindings and add them as Dart regression tests.

This hybrid approach ensures that both the Dart layer and the native layer are exercised.


#### 2.2.5 In-Process vs. Out-of-Process

| Mode | Use Case | Notes |
|------|----------|-------|
| In-process | Local developer runs, short CI runs | Fast; share Dart VM state; must reset per input. |
| Out-of-process | Nightly long runs, crash isolation | Spawn a fresh Dart process per input; slower but avoids pollution. |

For state-machine fuzzing, in-process is acceptable if the harness constructs a fresh object for every input. For connection-level fuzzing, prefer out-of-process to catch resource leaks and hangs.

---


### 2.3 Corpus Management


#### 2.3.1 Seed Corpus

A seed corpus provides valid and near-valid inputs that guide the fuzzer toward interesting code paths.

| Source | Contents | Location |
|--------|----------|----------|
| RFC test vectors | RFC 9000 Appendix A, RFC 9001 Appendix A sample packets | `fuzz/corpus/seed/rfc/` |
| Unit test fixtures | Valid packets, frames, and headers from existing tests | `fuzz/corpus/seed/unit/` |
| Handshake captures | Synthetic client/server handshake recordings | `fuzz/corpus/seed/handshake/` |
| QPACK static table | Encoded samples using all static table entries | `fuzz/corpus/seed/qpack/` |
| HTTP/3 samples | Request/response HEADERS and DATA frames | `fuzz/corpus/seed/http3/` |

Each seed corpus entry MUST be a small, self-contained file. Prefer binary files for raw packets and text files for human-readable fixtures where appropriate.


#### 2.3.2 Coverage Corpus

The coverage corpus is the set of inputs that the fuzzer has discovered during a run and that exercise distinct code paths. It is a superset of the seed corpus and grows over time.

- Store the coverage corpus in `fuzz/corpus/coverage/<target>/`.
- Add new interesting inputs to the coverage corpus after each successful nightly run.
- Run the full unit and component test suites with the coverage corpus as additional inputs at least weekly.


#### 2.3.3 Corpus Minimization

Periodically minimize the coverage corpus to reduce redundancy and CI runtime:

- For Dart-structured corpora, implement a minimization pass that removes any input whose behavior is already reproduced by a smaller input in the corpus.
- For native AFL++/libFuzzer corpora, use the tool's built-in minimizers (`afl-cmin`, `llvm-libfuzzer -merge=1`).
- Minimize the corpus before committing it to version control or before a major release.


#### 2.3.4 Corpus Versioning

- Keep seed corpus files in the repository (they are small and stable).
- Store large nightly coverage corpora outside the repository (e.g., CI artifacts, S3/GCS bucket) and link them in the documentation.
- Document the corpus version (e.g., `corpus-v2`) in the fuzzing CI job.

---


### 2.4 CI Integration and Schedule


#### 2.4.1 Pipeline Stages

| Stage | Trigger | Duration | Target |
|-------|---------|----------|--------|
| Quick fuzz smoke | Every PR (if network/parser code changes) | 2 minutes | Packet parser + frame parser only. |
| Daily fuzz | Nightly on `main` | 30 minutes per target | All targets. |
| Weekly deep fuzz | Weekend schedule | 2 hours per target | All targets + HTTP/3 + QPACK. |
| Pre-release fuzz | Release branch | 4 hours per target | Full corpus + native shims. |
| Native fuzz | Weekly (if native bindings exist) | 1 hour | AFL++/libFuzzer on FFI shims. |


#### 2.4.2 CI Configuration Requirements

- Run fuzz jobs on a dedicated runner with sufficient CPU and memory; avoid sharing with performance benchmarks.
- Use a stable Dart SDK version matching the project constraints.
- Collect and archive crash artifacts (seed, input bytes, stack trace) for any failure.
- Timeout each fuzz target per input: **5 seconds** default, **30 seconds** for connection-level targets.
- Halt on the first crash and report it; do not continue fuzzing the same target to avoid duplicate noise.


#### 2.4.3 Coverage Reporting

- Generate a Dart coverage report from the full fuzz corpus at least weekly.
- Compare parser coverage against the previous week; investigate any drop in coverage.
- Aim for each fuzz target to exercise at least 70% of the reachable code of its target parser/state machine.

---


### 2.5 Bug Triage and Regression Test Process


#### 2.5.1 Receiving a Fuzz Failure

A fuzz failure is reported with:

1. The target name.
2. The random seed or input file that reproduces the failure.
3. The Dart SDK version and commit hash.
4. The stack trace or error message.
5. Whether the failure is reproducible deterministically.


#### 2.5.2 Triage Steps

1. **Reproduce locally** using the reported seed or input.
2. **Minimize** the input to the smallest failing case.
3. **Classify** the failure:
   - Crash (uncaught exception, segfault, OOM)
   - Hang (infinite loop or timeout)
   - Correctness bug (invariant violation, wrong state transition)
   - Security issue (memory corruption, information leak, amplification)
4. **Assess impact**: Can the failure be triggered by a remote peer? Does it affect availability, integrity, or confidentiality?
5. **File an issue** with the `fuzz` label, severity, and minimized reproduction.


#### 2.5.3 Fix and Regression Test

1. Fix the root cause.
2. Add a deterministic unit test using the minimized input as the test fixture. This test MUST fail before the fix and pass after the fix.
3. Add the minimized input to the seed corpus so it is re-fuzzed regularly.
4. Run the relevant fuzz target for an extended period (at least 10 minutes) after the fix to ensure no related bugs remain.
5. Close the fuzz issue only after the regression test and the extended fuzz run pass.


#### 2.5.4 Regression Monitoring

- Maintain a `fuzz/regressions/` directory containing one test file per historically fixed fuzz bug.
- The CI unit test job MUST run all regression tests on every commit.
- Never remove a regression test without a documented reason and maintainer approval.

---



## 3. Acceptance Criteria

- [ ] Fuzz targets exist for every component listed in Section 2.
- [ ] A seed corpus is committed under `fuzz/corpus/seed/` with at least 10 entries per target.
- [ ] A coverage corpus is generated and stored by the nightly CI job.
- [ ] Daily fuzz job runs on `main` for at least 30 minutes per target without crashes.
- [ ] A deterministic regression test exists for every fuzz-discovered bug that has been fixed.
- [ ] Parser coverage from the fuzz corpus is measured weekly and does not decrease without explanation.
- [ ] Crash artifacts (seed, input, stack trace) are automatically archived by CI.
- [ ] Developers can run any fuzz target locally with a single command documented in the developer guide.
- [ ] No crashes, hangs, or security-relevant failures for 7 consecutive days before the fuzzing spec is considered satisfied.

---





## 4. Security Considerations

- Fuzz targets must never use production certificates, keys, or real network endpoints.
- Any fuzz-discovered crash in a network-facing parser MUST be treated as a potential security issue until proven otherwise.
- Do not include sensitive data (real packet captures, production keys) in the corpus.
- Fuzzing of the TLS layer should focus on the QUIC integration points, not on replacing TLS 1.3's own fuzzing; rely on the TLS library's upstream test suite for deep TLS fuzzing.

---





## 5. Dependencies

- `package:test` — Dart test harness for fuzzing and regression tests.
- `dart:io` / `dart:isolate` — for out-of-process fuzzing and runner scripts.
- AFL++ or libFuzzer — only if native FFI shims are fuzzed.
- `tc`/`netem` or in-process simulator — for connection-level fuzzing under network impairment (optional).

---















## Used By

No direct spec dependents. Referenced from architecture documents.
## 6. References

- `TESTING_SPEC.md` — overall testing strategy and links to this document.
- `PERFORMANCE_BENCHMARKING.md` — companion performance specification.
- `SECURITY_SPEC.md` — threat model and security mitigations that inform fuzzing priorities.
- `QUIC_CRYPTO_SPEC.md` — cryptographic primitives and transport parameters to fuzz.
- `QUIC_STREAMS_SPEC.md` — stream state machine invariants to fuzz.
- RFC 9000, RFC 9001, RFC 9002, RFC 9114 (HTTP/3), RFC 9204 (QPACK).
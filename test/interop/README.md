# QUIC Interop Tests

This directory contains the interop test matrix scaffold for `quic_lib`
(ROADMAP.md item #8).

The last formal interop pass was performed at **v1.0.0**. A loopback
end-to-end test was added at **v1.12.1**. The ROADMAP calls for re-running
interop against the current versions of the major QUIC reference
implementations. Because the reference implementations cannot be installed
in every environment, this directory provides:

- **`interop_matrix.dart`** — a plain data structure describing the
  interop matrix (reference implementations × features × status).
- **`interop_test.dart`** — runnable scaffold tests that detect whether
  each reference binary is available, skip cleanly when it is not, and
  run a minimal probe when it is.

The scaffold is intentionally green when no reference implementations are
installed: the per-reference tests short-circuit with a skip-style return
rather than failing.

## The interop matrix

The matrix is the product of:

| Reference implementation | Features |
| --- | --- |
| quic-go | handshake, 1-RTT data, stream multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport |
| aioquic | handshake, 1-RTT data, stream multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport |
| ngtcp2 | handshake, 1-RTT data, stream multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport |
| cloudflare-quiche | handshake, 1-RTT data, stream multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport |
| msquic | handshake, 1-RTT data, stream multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport |

Each cell carries a status of `pass`, `fail`, `untested`, or `blocked`.
The scaffold ships with every cell marked `untested`; a real interop pass
updates the statuses in `interop_matrix.dart`.

## Running the interop tests

From the repository root:

```powershell
dart test test/interop/interop_test.dart
```

Or as part of the full suite:

```powershell
dart test test/all_tests.dart
```

When a reference binary is not on the `PATH`, the corresponding test
prints an install hint via `printOnFailure` and returns without failing.
When the binary is present, the scaffold invokes it with `--help` as a
minimal liveness probe. A real Initial-packet exchange is left as a
`TODO(interop)` hook for per-reference harness scripts.

## Installing the reference implementations

| Implementation | Install hint |
| --- | --- |
| [quic-go](https://github.com/lucas-clemente/quic-go) | `go install github.com/lucas-clemente/quic-go/example/...@latest` |
| [aioquic](https://github.com/aiortc/aioquic) | `pip install aioquic` |
| [ngtcp2](https://github.com/ngtcp2/ngtcp2) | Build from source; see the project README |
| [cloudflare-quiche](https://github.com/cloudflare/quiche) | Build from source; see the project README |
| [msquic](https://github.com/microsoft/msquic) | Build from source; see the project README |

On Windows, binary detection uses `where`; on POSIX systems it uses
`which`. Ensure the relevant executable is on your `PATH` before running
the tests.

## Updating the matrix

After running a real interop pass:

1. Update the `status` (and optional `note`) for each affected entry in
   `interop_matrix.dart`.
2. Re-run `dart test test/interop/interop_test.dart` — the
   well-formedness tests enforce that the matrix remains complete (one
   entry per implementation × feature pair) and that the scaffold still
   ships fully `untested` until statuses are explicitly updated.
3. Commit the matrix update and reference it from the ROADMAP item.

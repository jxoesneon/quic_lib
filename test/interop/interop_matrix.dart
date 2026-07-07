/// Interop test matrix for `quic_lib`.
///
/// This file defines the data structures that describe the interop test
/// matrix used to track compatibility between `quic_lib` and the major
/// QUIC reference implementations. The matrix is the product of:
///
/// * a set of [ReferenceImplementation]s (quic-go, aioquic, ngtcp2,
///   cloudflare-quiche, msquic), and
/// * a set of [InteropFeature]s (handshake, 1-RTT data, stream
///   multiplexing, connection migration, 0-RTT, HTTP/3, WebTransport).
///
/// Each combination is recorded as an [InteropMatrixEntry] with a
/// [InteropStatus] describing the last recorded outcome.
///
/// The matrix is intentionally a plain data structure so that:
///
/// * `interop_test.dart` can validate it is well-formed, and
/// * future tooling can render it as a Markdown table or feed it into
///   the upstream QUIC interop runner.
///
/// See `test/interop/README.md` for how to run the interop tests and how
/// to install the reference implementations.

/// A QUIC feature exercised by the interop matrix.
enum InteropFeature {
  /// TLS 1.3 handshake completion (RFC 9001 §4).
  handshake,

  /// Exchange of 1-RTT application data after the handshake.
  oneRttData,

  /// Concurrent bidirectional and unidirectional streams.
  streamMultiplexing,

  /// Client-side connection migration across paths (RFC 9000 §9.3).
  connectionMigration,

  /// 0-RTT early data replay (RFC 9001 §2.3).
  zeroRtt,

  /// HTTP/3 request/response (RFC 9114).
  http3,

  /// WebTransport over HTTP/3 (RFC 9220).
  webTransport,
}

/// The recorded outcome of an interop matrix cell.
enum InteropStatus {
  /// The interop check passed.
  pass,

  /// The interop check failed.
  fail,

  /// The interop check has not been run yet.
  untested,

  /// The interop check cannot run because of an external blocker
  /// (e.g. the reference implementation lacks the feature).
  blocked,
}

/// A reference QUIC implementation tracked by the interop matrix.
class ReferenceImplementation {
  /// Creates a reference implementation descriptor.
  const ReferenceImplementation({
    required this.name,
    required this.binary,
    required this.installHint,
    required this.homepage,
  });

  /// Human-readable name, e.g. `quic-go`.
  final String name;

  /// Executable name or known path used to detect availability via
  /// `which`/`where`. Examples: `quicgo`, `aioquic`, `ngtcp2-client`.
  final String binary;

  /// Short install hint shown in skip messages and the README.
  final String installHint;

  /// URL of the project homepage.
  final String homepage;
}

/// A single cell of the interop matrix: the recorded [status] of
/// [feature] against [implementation].
class InteropMatrixEntry {
  /// Creates a matrix entry.
  const InteropMatrixEntry({
    required this.implementation,
    required this.feature,
    required this.status,
    this.note,
  });

  /// The reference implementation under test.
  final ReferenceImplementation implementation;

  /// The feature under test.
  final InteropFeature feature;

  /// The last recorded outcome.
  final InteropStatus status;

  /// Optional free-form note (e.g. a ticket reference or version).
  final String? note;
}

/// The reference implementations tracked by the matrix.
const List<ReferenceImplementation> referenceImplementations =
    <ReferenceImplementation>[
  ReferenceImplementation(
    name: 'quic-go',
    binary: 'quicgo',
    installHint:
        'go install github.com/lucas-clemente/quic-go/example/...@latest',
    homepage: 'https://github.com/lucas-clemente/quic-go',
  ),
  ReferenceImplementation(
    name: 'aioquic',
    binary: 'aioquic',
    installHint: 'pip install aioquic',
    homepage: 'https://github.com/aiortc/aioquic',
  ),
  ReferenceImplementation(
    name: 'ngtcp2',
    binary: 'ngtcp2-client',
    installHint: 'See https://github.com/ngtcp2/ngtcp2 build instructions',
    homepage: 'https://github.com/ngtcp2/ngtcp2',
  ),
  ReferenceImplementation(
    name: 'cloudflare-quiche',
    binary: 'quiche-client',
    installHint: 'See https://github.com/cloudflare/quiche build instructions',
    homepage: 'https://github.com/cloudflare/quiche',
  ),
  ReferenceImplementation(
    name: 'msquic',
    binary: 'msquic',
    installHint: 'See https://github.com/microsoft/msquic build instructions',
    homepage: 'https://github.com/microsoft/msquic',
  ),
];

/// All features exercised by the matrix.
const List<InteropFeature> interopFeatures = <InteropFeature>[
  InteropFeature.handshake,
  InteropFeature.oneRttData,
  InteropFeature.streamMultiplexing,
  InteropFeature.connectionMigration,
  InteropFeature.zeroRtt,
  InteropFeature.http3,
  InteropFeature.webTransport,
];

/// The full interop matrix as a flat list of entries.
///
/// Every combination of [referenceImplementations] x [interopFeatures]
/// must have exactly one entry here; `interop_test.dart` validates this
/// invariant. Until a real interop pass is performed against the current
/// reference versions, cells are marked [InteropStatus.untested].
final List<InteropMatrixEntry> interopMatrix = <InteropMatrixEntry>[
  for (final impl in referenceImplementations)
    for (final feature in interopFeatures)
      InteropMatrixEntry(
        implementation: impl,
        feature: feature,
        status: InteropStatus.untested,
        note: 'Pending re-run against current reference version',
      ),
];

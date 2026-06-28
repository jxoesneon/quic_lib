/// A pure-Dart QUIC transport implementation.
///
/// This library exposes the core QUIC transport layer without the higher-level
/// protocols (HTTP/3, WebTransport, or libp2p). Use it when you need direct
/// control over endpoints, connections, streams, and scheduling.
///
/// Exports include:
/// * [QuicEndpoint] — bind to a local address and accept or initiate connections.
/// * [QuicConnection] — state machine, stream allocation, and recovery.
/// * [UdpSocket] — the underlying UDP I/O abstraction.
/// * [ConnectionIsolate] and [IsolateSupervisor] — per-connection isolate management.
/// * [StreamScheduler] / [RoundRobinScheduler] — stream scheduling policies.
/// * [QuicVersions] — supported QUIC protocol versions.
///
/// Prefer importing `package:quic_lib/quic_lib.dart` when you need the entire
/// public API (crypto, wire format, HTTP/3, WebTransport, libp2p). Import
/// this barrel when your application only needs the transport primitives.
///
/// See also:
/// * `quic_lib.dart` — the full public API.
/// * `http3.dart` — HTTP/3 built on this transport.
/// * `webtransport.dart` — WebTransport over HTTP/3.
library;

export 'src/io/quic_endpoint.dart' show QuicEndpoint;
export 'src/connection/quic_connection.dart' show QuicConnection;
export 'src/connection/connection_state_machine.dart' show ConnectionState;
export 'src/connection/congestion_control/congestion_controller.dart'
    show CongestionController;
export 'src/connection/congestion_control/cubic.dart'
    show CubicCongestionController;
export 'src/connection/congestion_control/bbr.dart'
    show BbrCongestionController, BbrState;
export 'src/connection/congestion_control/hystart.dart' show Hystart;
export 'src/io/udp_socket.dart' show UdpSocket;
export 'src/libp2p/multiaddr.dart' show Multiaddr;
export 'src/streams/stream_scheduler.dart' show StreamScheduler;
export 'src/streams/round_robin_scheduler.dart' show RoundRobinScheduler;
export 'src/io/connection_isolate.dart' show ConnectionIsolate;
export 'src/io/isolate_supervisor.dart' show IsolateSupervisor;
export 'src/wire/quic_versions.dart' show QuicVersions;

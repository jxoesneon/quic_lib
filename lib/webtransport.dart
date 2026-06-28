/// WebTransport support over QUIC.
///
/// Implements [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) and the
/// WebTransport HTTP/3 protocol. This barrel exposes session management,
/// capsule types, and stream registration for building WebTransport clients
/// and servers.
///
/// Exports include:
/// * [WebTransportSession] — per-session state, datagrams, and graceful close.
/// * [WebTransportSessionManager] — creates, routes, and cleans up sessions.
/// * [CapsuleType] / [Capsule] — WebTransport control capsules (CLOSE, DRAIN,
///   GOAWAY, REGISTER_STREAM, DATAGRAM).
/// * [WebTransportStreamId] / [WebTransportStreamType] — stream identifiers.
///
/// Use this library when you need WebTransport semantics (unreliable datagrams
/// and reliable streams) over HTTP/3. For the underlying QUIC transport, import
/// `quic.dart`. For the full stack including HTTP/3 and libp2p, import
/// `quic_lib.dart`.
///
/// See also:
/// * `quic_lib.dart` — the full public API.
/// * `quic.dart` — QUIC transport primitives.
/// * `http3.dart` — HTTP/3 layer used by WebTransport.
library;

export 'src/webtransport/webtransport_session.dart' show WebTransportSession;
export 'src/webtransport/webtransport_session_manager.dart'
    show WebTransportSessionManager;
export 'src/webtransport/capsule_types.dart' show CapsuleType, Capsule;
export 'src/webtransport/capsule_router.dart' show CapsuleRouter;
export 'src/webtransport/goaway_capsule.dart' show GoawayCapsule;
export 'src/webtransport/stream_capsule.dart' show StreamCapsule;
export 'src/webtransport/datagram_capsule.dart' show DatagramCapsule;
export 'src/webtransport/stream_types.dart'
    show WebTransportStreamId, WebTransportStreamType;

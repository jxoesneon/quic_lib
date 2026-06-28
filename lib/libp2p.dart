/// libp2p transport backed by QUIC.
///
/// This library provides a [libp2p](https://libp2p.io) transport layer that
/// uses QUIC as the underlying protocol. It wraps [QuicEndpoint] with
/// libp2p-style `dial`/`listen` APIs, multiaddr parsing, and peer identity
/// handling.
///
/// Exports include:
/// * [Libp2pQuicTransport] — dial remote peers and listen on multiaddrs.
/// * [Libp2pQuicConnection] — a libp2p-friendly wrapper around [QuicConnection].
/// * [Multiaddr] / [MultiaddrComponent] — parse and serialize multiaddrs such as
///   `/ip4/127.0.0.1/udp/4433/quic-v1`.
/// * [PeerId] — base58/base36 encoding and decoding of libp2p peer identities.
/// * [DCUtRStateMachine] — Direct Connection Upgrade through Relay state machine.
///
/// Use this library when integrating with a libp2p network. For the underlying
/// QUIC primitives, import `quic.dart`. For the full stack, import `quic_lib.dart`.
///
/// See also:
/// * `quic_lib.dart` — the full public API.
/// * `quic.dart` — QUIC transport primitives.
library;

export 'src/libp2p/peer_id.dart' show PeerId;
export 'src/libp2p/multiaddr.dart' show Multiaddr, MultiaddrComponent;
export 'src/libp2p/dcutr_state_machine.dart' show DCUtRStateMachine;
export 'src/libp2p/libp2p_quic_transport.dart'
    show Libp2pQuicTransport, Libp2pQuicConnection;

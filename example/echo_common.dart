import 'package:quic_lib/quic_lib.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart' as hke;

/// Shared configuration for the loopback echo example.
///
/// The example uses a fixed test destination connection ID and pre-shared
/// application keys so that two separate processes can perform a real
/// encrypted QUIC round-trip over loopback without requiring a full TLS
/// handshake. This is the same technique used by the package's end-to-end
/// tests. A production QUIC deployment would complete a real handshake and
/// derive fresh 1-RTT keys.
const List<int> echoTestDcid = <int>[
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
];

const String echoMessage = 'Hello, QUIC!';
const int echoServerPort = 12345;

/// Role of an endpoint in the echo example.
enum EchoRole { client, server }

/// Creates a [QuicConnection] with deterministic application-space keys.
///
/// [role] must be [EchoRole.client] for the client and [EchoRole.server] for
/// the server so that the directional send/receive keys line up correctly.
Future<QuicConnection> createEchoConnection({required EchoRole role}) async {
  final backend = DefaultCryptoBackend();
  final handshakeRole = role == EchoRole.client
      ? hke.HandshakeRole.client
      : hke.HandshakeRole.server;
  final keyManager = await KeyManager.forTestWithKeys(
    role: handshakeRole,
    backend: backend,
  );

  return QuicConnection(
    stateMachine: ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
    keyManager: keyManager,
  );
}

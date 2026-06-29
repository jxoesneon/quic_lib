import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';

QuicConnection _createConnection({
  KeyManager? keyManager,
  HandshakeRole role = HandshakeRole.server,
}) {
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

void main() {
  group('v1.5.0 peer-initiated key update detection', () {
    test('QuicConnection detects peer-initiated key update', () async {
      final serverKeyManager = await KeyManager.forTestWithKeys(
        role: HandshakeRole.server,
      );
      final clientKeyManager = await KeyManager.forTestWithKeys(
        role: HandshakeRole.client,
      );

      final server = _createConnection(
        keyManager: serverKeyManager,
        role: HandshakeRole.server,
      );
      final client = _createConnection(
        keyManager: clientKeyManager,
        role: HandshakeRole.client,
      );

      // Use a shared DCID for both endpoints so the short-header DCID length matches.
      final dcid = List<int>.filled(8, 0xAB);

      // Server initiates a key update; its local key phase becomes 1.
      await serverKeyManager.initiateKeyUpdate();
      expect(serverKeyManager.keyPhase, 1);
      expect(clientKeyManager.keyPhase, 0);

      // Server sends a 1-RTT packet with the updated key phase.
      final packet = await server.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [PingFrame(), PaddingFrame(length: 32)],
        dcid: dcid,
      );

      // Client processes the encrypted datagram. The key phase bit differs from
      // the client's current phase, so a peer-initiated key update is detected.
      final processed = await client.processEncryptedDatagram(packet);
      expect(processed, 1);
      expect(clientKeyManager.keyPhase, 1);
      expect(clientKeyManager.keyUpdatePending, isTrue);

      // The client's first send with the updated keys confirms the peer update.
      await client.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [PingFrame(), PaddingFrame(length: 32)],
        dcid: dcid,
      );
      expect(clientKeyManager.keyUpdatePending, isFalse);
    });

    test('QuicConnection decrypts same-phase packets after local update',
        () async {
      final serverKeyManager = await KeyManager.forTestWithKeys(
        role: HandshakeRole.server,
      );
      final clientKeyManager = await KeyManager.forTestWithKeys(
        role: HandshakeRole.client,
      );

      final server = _createConnection(
        keyManager: serverKeyManager,
        role: HandshakeRole.server,
      );
      final client = _createConnection(
        keyManager: clientKeyManager,
        role: HandshakeRole.client,
      );

      final dcid = List<int>.filled(8, 0xAB);

      // Both endpoints update independently (simultaneous key update).
      await serverKeyManager.initiateKeyUpdate();
      await clientKeyManager.initiateKeyUpdate();
      expect(serverKeyManager.keyPhase, 1);
      expect(clientKeyManager.keyPhase, 1);

      final packet = await server.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [PingFrame(), PaddingFrame(length: 32)],
        dcid: dcid,
      );

      final processed = await client.processEncryptedDatagram(packet);
      expect(processed, 1);
      expect(clientKeyManager.keyPhase, 1);
    });
  });
}

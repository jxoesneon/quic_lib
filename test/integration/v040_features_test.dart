import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/tls/certificate_verifier.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/streams/stream_id.dart';
import 'package:dart_quic/src/streams/stream_manager.dart';
import 'package:dart_quic/src/wire/frame.dart';

/// Integration tests for dart_quic v0.4.0 features.
void main() {
  group('Connection ID rotation', () {
    test('generateNewConnectionIdFrame returns a NewConnectionIdFrame', () {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      final frame = conn.generateNewConnectionIdFrame();
      expect(frame, isA<NewConnectionIdFrame>());
    });
  });

  group('Flow control', () {
    test('StreamManager has flow controllers for new streams', () {
      final manager = StreamManager();
      const streamId = 0;

      // Simulate receiving a STREAM frame to create the stream.
      manager.onStreamFrame(
        StreamFrame(
          streamId: streamId,
          data: [0x01, 0x02, 0x03],
        ),
      );

      final sendController = manager.getSendFlowController(streamId);
      final receiveController = manager.getReceiveFlowController(streamId);

      expect(sendController, isNotNull);
      expect(receiveController, isNotNull);
    });
  });

  group('0-RTT', () {
    test('canSendZeroRtt is false on a fresh connection', () {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      expect(conn.canSendZeroRtt, isFalse);
    });
  });

  group('Pacing', () {
    test('shouldPacePackets reflects congestion window state', () {
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      // Default cwnd is 2400, so pacing should not be active.
      expect(conn.shouldPacePackets, isFalse);

      // Increase cwnd above 2*packetSize (2400).
      conn.pacingCalculator.updateCongestionWindow(3000);
      expect(conn.shouldPacePackets, isTrue);
    });
  });

  group('Certificate chain', () {
    test('verifyCertificateChain returns true for empty chain', () {
      final backend = DefaultCryptoBackend();
      final verifier = CertificateVerifier(backend);
      final trustedRoot = _SimplePublicKey([0xAA]);

      final result = verifier.verifyCertificateChain([], trustedRoot);
      expect(result, isTrue);
    });
  });
}

/// Minimal local implementation of [PublicKey] so this test file is self-contained.
class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/streams/stream_id.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';

void main() {
  group('QuicConnection', () {
    QuicConnection _createConnection() {
      return QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
    }

    test('construction with all subsystems', () {
      final conn = _createConnection();
      expect(conn, isNotNull);
    });

    test('initial state is idle', () {
      final conn = _createConnection();
      expect(conn.state, equals(ConnectionState.idle));
    });

    test('openBidirectionalStream returns valid stream ID', () {
      final conn = _createConnection();
      final id = conn.openBidirectionalStream();
      expect(id, equals(0)); // First client bidi
      expect(StreamId.isBidirectional(id), isTrue);
      expect(StreamId.isClientInitiated(id), isTrue);
    });

    test('openUnidirectionalStream returns valid stream ID', () {
      final conn = _createConnection();
      final id = conn.openUnidirectionalStream();
      expect(id, equals(2)); // First client uni
      expect(StreamId.isUnidirectional(id), isTrue);
      expect(StreamId.isClientInitiated(id), isTrue);
    });

    test('close transitions to closing', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      sm.transitionTo(ConnectionState.established);
      final conn = QuicConnection(
        stateMachine: sm,
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
      conn.close();
      expect(conn.state, equals(ConnectionState.closing));
    });

    test('allocatePacketNumber returns sequential numbers', () {
      final conn = _createConnection();
      final pn1 = conn.allocatePacketNumber(PacketNumberSpace.initial);
      final pn2 = conn.allocatePacketNumber(PacketNumberSpace.initial);
      expect(pn2, equals(pn1 + 1));
    });

    test('canSend respects anti-amplification limit before validation', () {
      final conn = _createConnection();
      // No bytes received yet, so send budget is 0.
      expect(conn.canSend(1), isFalse);

      // Receive 100 bytes → budget = 300.
      conn.onBytesReceived(100);
      expect(conn.canSend(300), isTrue);
      expect(conn.canSend(301), isFalse);
    });

    test('validateAddress removes anti-amplification limit', () {
      final conn = _createConnection();
      conn.onBytesReceived(100);
      expect(conn.canSend(1000), isFalse);

      conn.validateAddress();
      expect(conn.canSend(1000), isTrue);
    });

    test('onBytesSent reduces send budget', () {
      final conn = _createConnection();
      conn.onBytesReceived(100);
      expect(conn.sendBudget, equals(300));
      conn.onBytesSent(50);
      expect(conn.sendBudget, equals(250));
    });
  });
}

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/streams/stream_id.dart';
import 'package:dart_quic/src/streams/flow_controller.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/rtt_estimator.dart';
import 'package:dart_quic/src/recovery/loss_detector.dart';
import 'package:dart_quic/src/recovery/pto_scheduler.dart';
import 'package:dart_quic/src/recovery/congestion_controller.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:dart_quic/src/wire/packet_header.dart';

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

Uint8List _buildDatagram(List<Frame> frames) {
  final payload = Uint8List.fromList(frames.expand((f) => f.serialize()).toList());
  final header = ShortHeader(
    destinationConnectionId: Uint8List(8),
    packetNumber: 0,
    packetNumberLength: 1,
    payload: payload,
  );
  return header.serialize();
}

void main() {
  group('Flow control frame dispatch', () {
    test('MAX_DATA updates connection flow controller limit', () {
      final conn = _createConnection();
      expect(conn.connectionFlowController.availableWindow, equals(65536));

      final datagram = _buildDatagram([MaxDataFrame(maxData: 100000)]);
      conn.processIncomingDatagram(datagram);

      expect(conn.connectionFlowController.availableWindow, equals(100000));
    });

    test('MAX_STREAM_DATA updates stream flow controller via StreamManager', () {
      final conn = _createConnection();
      const streamId = 0;

      // Create the stream by delivering a STREAM frame.
      final createDatagram = _buildDatagram([
        StreamFrame(streamId: streamId, data: Uint8List(0), hasExplicitLength: true),
      ]);
      conn.processIncomingDatagram(createDatagram);

      final initialWindow = conn.streamManager.getSendFlowController(streamId)!.availableWindow;
      expect(initialWindow, equals(65536));

      final updateDatagram = _buildDatagram([
        MaxStreamDataFrame(streamId: streamId, maxStreamData: 200000),
      ]);
      conn.processIncomingDatagram(updateDatagram);

      final updatedWindow = conn.streamManager.getSendFlowController(streamId)!.availableWindow;
      expect(updatedWindow, equals(200000));
    });

    test('connection flow controller available via getter', () {
      final conn = _createConnection();
      expect(conn.connectionFlowController, isNotNull);
      expect(conn.connectionFlowController, isA<FlowController>());
    });

    test('multiple MAX_DATA frames compound the limit', () {
      final conn = _createConnection();
      expect(conn.connectionFlowController.availableWindow, equals(65536));

      conn.processIncomingDatagram(_buildDatagram([MaxDataFrame(maxData: 100000)]));
      expect(conn.connectionFlowController.availableWindow, equals(100000));

      // Lower limit should be ignored.
      conn.processIncomingDatagram(_buildDatagram([MaxDataFrame(maxData: 50000)]));
      expect(conn.connectionFlowController.availableWindow, equals(100000));

      // Higher limit should update.
      conn.processIncomingDatagram(_buildDatagram([MaxDataFrame(maxData: 150000)]));
      expect(conn.connectionFlowController.availableWindow, equals(150000));
    });
  });
}

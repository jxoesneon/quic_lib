import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/connection/quic_connection.dart';
import 'package:dart_quic/src/connection/connection_state_machine.dart';
import 'package:dart_quic/src/connection/connection_id_manager.dart';
import 'package:dart_quic/src/connection/packet_receiver.dart';
import 'package:dart_quic/src/streams/stream_id.dart';
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

Uint8List _buildResponseDatagram(List<int> challengeData, List<int> dcid) {
  final frames = <Frame>[PathResponseFrame(data: challengeData)];
  final payload = Uint8List.fromList(frames.expand((f) => f.serialize()).toList());
  final header = ShortHeader(
    destinationConnectionId: dcid,
    packetNumber: 0,
    packetNumberLength: 1,
    payload: payload,
  );
  return header.serialize();
}

void main() {
  group('QuicConnection path probing', () {
    test('probeNewPath generates a PATH_CHALLENGE packet', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);
      final future = conn.probeNewPath(dcid);
      expect(conn.lastProbePacket, isNotNull);
      expect(conn.lastProbePacket!.length, greaterThan(0));

      // Clean up: complete the future so it does not hang.
      final result = PacketReceiver.processPacket(conn.lastProbePacket!);
      final challengeFrame = result!.frames.whereType<PathChallengeFrame>().first;
      final responseDatagram = _buildResponseDatagram(challengeFrame.data, dcid);
      conn.processIncomingDatagram(responseDatagram);
      await future;
    });

    test('isProbingPath is true after probeNewPath', () async {
      final conn = _createConnection();
      expect(conn.isProbingPath, isFalse);
      final future = conn.probeNewPath(List<int>.filled(8, 0));
      expect(conn.isProbingPath, isTrue);

      // Clean up
      final result = PacketReceiver.processPacket(conn.lastProbePacket!);
      final challengeFrame = result!.frames.whereType<PathChallengeFrame>().first;
      final responseDatagram = _buildResponseDatagram(challengeFrame.data, List<int>.filled(8, 0));
      conn.processIncomingDatagram(responseDatagram);
      await future;
    });

    test('isProbingPath is false after path validation', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);
      final future = conn.probeNewPath(dcid);
      expect(conn.isProbingPath, isTrue);

      final result = PacketReceiver.processPacket(conn.lastProbePacket!);
      final challengeFrame = result!.frames.whereType<PathChallengeFrame>().first;
      final responseDatagram = _buildResponseDatagram(challengeFrame.data, dcid);
      conn.processIncomingDatagram(responseDatagram);

      await future;
      expect(conn.isProbingPath, isFalse);
    });

    test('Packet contains a PathChallengeFrame', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);
      final future = conn.probeNewPath(dcid);

      final result = PacketReceiver.processPacket(conn.lastProbePacket!);
      expect(result, isNotNull);
      final challengeFrames = result!.frames.whereType<PathChallengeFrame>();
      expect(challengeFrames, hasLength(1));
      expect(challengeFrames.first.data.length, equals(8));

      // Clean up
      final responseDatagram = _buildResponseDatagram(challengeFrames.first.data, dcid);
      conn.processIncomingDatagram(responseDatagram);
      await future;
    });
  });
}

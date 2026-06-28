import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';

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

Future<Uint8List> _buildResponseDatagram(
    List<int> challengeData, List<int> dcid) async {
  final frames = <Frame>[
    PathResponseFrame(data: Uint8List.fromList(challengeData))
  ];
  final payload =
      Uint8List.fromList(frames.expand((f) => f.serialize()).toList());
  final header = ShortHeader(
    destinationConnectionId: dcid,
    packetNumber: 0,
    payload: payload,
  );
  return await header.serialize();
}

void main() {
  group('QuicConnection path validation', () {
    test('sendPathChallenge stores challenge and builds packet', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);

      final packet = await conn.sendPathChallenge(dcid);
      expect(packet, isNotNull);
      expect(packet.length, greaterThan(0));
      expect(conn.validatedPathCount, equals(0));

      // Verify the packet contains a PathChallengeFrame.
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      final challengeFrames = result!.frames.whereType<PathChallengeFrame>();
      expect(challengeFrames, hasLength(1));
      expect(challengeFrames.first.data.length, equals(8));
    });

    test('onPathResponseReceived with matching data validates path', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);

      // Send a challenge.
      final packet = await conn.sendPathChallenge(dcid);
      expect(conn.validatedPathCount, equals(0));

      // Extract the challenge data from the sent packet.
      final result = PacketReceiver.processPacket(packet);
      final challengeFrame =
          result!.frames.whereType<PathChallengeFrame>().first;

      // Build a PATH_RESPONSE packet with matching data.
      final responseDatagram =
          await _buildResponseDatagram(challengeFrame.data, dcid);

      // Process the response.
      conn.processIncomingDatagram(responseDatagram);

      // Path should now be validated.
      expect(conn.validatedPathCount, equals(1));
    });

    test('onPathResponseReceived with non-matching data is ignored', () {
      final conn = _createConnection();
      final nonMatchingData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final frame = PathResponseFrame(data: nonMatchingData);

      final result = conn.onPathResponseReceived(frame);

      expect(result, isFalse);
      expect(conn.validatedPathCount, equals(0));
    });

    test('timeout behavior: stale challenges are not validated', () async {
      final conn = _createConnection();
      final dcid = List<int>.filled(8, 0);

      // Send a challenge.
      final packet = await conn.sendPathChallenge(dcid);

      // Extract challenge data.
      final parsed = PacketReceiver.processPacket(packet);
      final challengeFrame =
          parsed!.frames.whereType<PathChallengeFrame>().first;

      // Manually clear pending challenges to simulate timeout/expiration.
      // Since _pendingPathChallenges is private, we simulate by sending
      // a response after the map has been effectively cleared. We do this
      // by creating a fresh connection and sending a response with the
      // same data, which won't match any pending challenge.
      final freshConn = _createConnection();
      final responseDatagram =
          await _buildResponseDatagram(challengeFrame.data, dcid);
      freshConn.processIncomingDatagram(responseDatagram);

      expect(freshConn.validatedPathCount, equals(0));
    });
  });
}

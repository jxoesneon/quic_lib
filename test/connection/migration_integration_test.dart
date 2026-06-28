import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/migration_helper.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';

void main() {
  group('MigrationHelper integration', () {
    QuicConnection _createConnection({ConnectionStateMachine? stateMachine}) {
      return QuicConnection(
        stateMachine: stateMachine ?? ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );
    }

    Uint8List _buildPacket(List<Frame> frames) {
      return PacketBuilder.build(
        ShortHeader(
          destinationConnectionId: [
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
          ],
          packetNumber: 0,
        ),
        frames,
      );
    }

    test(
        'processIncomingDatagram with PATH_CHALLENGE generates a pending challenge',
        () {
      final conn = _createConnection();
      final challengeData = [1, 2, 3, 4, 5, 6, 7, 8];
      final packet = _buildPacket([PathChallengeFrame(data: challengeData)]);

      expect(conn.getPendingChallenge(), isNull);
      conn.processIncomingDatagram(packet);
      expect(conn.getPendingChallenge(), isNotNull);
      expect(conn.getPendingChallenge()!.data.length, equals(8));
    });

    test('processIncomingDatagram with PATH_RESPONSE validates the path', () {
      final conn = _createConnection();
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final responsePacket = _buildPacket([
        PathResponseFrame(data: challenge.data),
      ]);

      expect(conn.isPathValidated(challenge.data), isFalse);
      conn.processIncomingDatagram(responsePacket);
      expect(conn.isPathValidated(challenge.data), isTrue);
    });

    test('isPathValidated returns true after response', () {
      final conn = _createConnection();
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final responsePacket = _buildPacket([
        PathResponseFrame(data: challenge.data),
      ]);

      expect(conn.isPathValidated(challenge.data), isFalse);
      conn.processIncomingDatagram(responsePacket);
      expect(conn.isPathValidated(challenge.data), isTrue);
    });

    test('onAddressValidated is called when path is validated', () {
      final sm = ConnectionStateMachine();
      sm.transitionTo(ConnectionState.handshaking);
      final conn = _createConnection(stateMachine: sm);
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final responsePacket = _buildPacket([
        PathResponseFrame(data: challenge.data),
      ]);

      expect(conn.state, equals(ConnectionState.handshaking));
      conn.processIncomingDatagram(responsePacket);
      expect(conn.state, equals(ConnectionState.established));
    });

    test('Expired challenges are cleaned up', () {
      final conn = _createConnection();
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);

      final expired = conn.migrationHelper.getExpiredChallenges(
        10000,
        timeoutUs: MigrationHelper.defaultTimeoutUs,
      );

      expect(expired.length, equals(1));
      expect(expired.first, equals(challenge.data));

      // After cleanup, the challenge should no longer validate.
      final response = PathResponseFrame(data: challenge.data);
      expect(conn.migrationHelper.onResponseReceived(response), isFalse);
    });
  });
}

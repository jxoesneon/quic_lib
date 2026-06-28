import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';

void main() {
  group('Full migration wiring', () {
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

    test('Endpoint.connect stores remote address', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final remoteAddress = InternetAddress.loopbackIPv4;
      final remotePort = 12345;

      final conn = await endpoint.connect(remoteAddress, remotePort);

      expect(endpoint.getRemoteAddress(conn), equals(remoteAddress));
      expect(endpoint.getRemotePort(conn), equals(remotePort));

      endpoint.close();
    });

    test('getRemoteAddress returns the correct address', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      final remoteAddress = InternetAddress.loopbackIPv4;

      final conn = await endpoint.connect(remoteAddress, 54321);

      expect(endpoint.getRemoteAddress(conn), isNotNull);
      expect(endpoint.getRemoteAddress(conn)?.address,
          equals(remoteAddress.address));

      endpoint.close();
    });

    test(
        'Processing PATH_CHALLENGE + PATH_RESPONSE validates path and increments validatedPathCount',
        () {
      final conn = _createConnection();
      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final responsePacket = _buildPacket([
        PathResponseFrame(data: challenge.data),
      ]);

      expect(conn.validatedPathCount, equals(0));
      expect(conn.isPathValidated(challenge.data), isFalse);

      conn.processIncomingDatagram(responsePacket);

      expect(conn.isPathValidated(challenge.data), isTrue);
      expect(conn.validatedPathCount, equals(1));
    });

    test('Path validation clears anti-amplification limit', () {
      final conn = _createConnection();
      conn.onBytesReceived(100);
      expect(conn.canSend(1000), isFalse);

      final challenge =
          conn.migrationHelper.generateChallenge(currentTimeUs: 0);
      final responsePacket = _buildPacket([
        PathResponseFrame(data: challenge.data),
      ]);

      conn.processIncomingDatagram(responsePacket);

      expect(conn.canSend(1000), isTrue);
    });
  });
}

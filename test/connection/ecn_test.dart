import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';

QuicConnection _createConnection({
  ConnectionStateMachine? stateMachine,
  ConnectionIdManager? cidManager,
  bool ecnEnabled = true,
}) {
  return QuicConnection(
    stateMachine: stateMachine ?? ConnectionStateMachine(),
    cidManager: cidManager ?? ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
    ecnEnabled: ecnEnabled,
  );
}

/// Build a raw short-header packet with the given [ecnBits] and [payload].
/// The packet number length is derived from [ecnBits] + 1 to match the
/// simulated ECN encoding in the last two bits.
Uint8List _buildShortHeaderPacket(int ecnBits, List<int> payload) {
  final dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
  // First byte: HF=0, FB=1, no spin, no key phase, PN length encoded by ecnBits
  final firstByte = 0x40 | ecnBits;
  final pnLen = ecnBits + 1;
  final pnBytes = List<int>.generate(pnLen, (_) => 0x00);
  return Uint8List.fromList([firstByte, ...dcid, ...pnBytes, ...payload]);
}

void main() {
  group('ShortHeader ECN serialization', () {
    test('ecnCapable=true sets ECN bits to ECT(0) or ECT(1)', () async {
      final header = ShortHeader(
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ecnCapable: true,
      );
      final packet = await header.serialize();
      final ecn = packet[0] & 0x03;
      expect(ecn, anyOf(equals(1), equals(2)));
    });

    test('ecnCapable=false sets ECN bits to Not-ECT', () async {
      final header = ShortHeader(
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ecnCapable: false,
      );
      final packet = await header.serialize();
      final ecn = packet[0] & 0x03;
      expect(ecn, equals(0));
    });

    test('ecnBits reflects serialized ECN value', () async {
      final header = ShortHeader(
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        ecnCapable: true,
      );
      await header.serialize();
      expect(header.ecnBits, anyOf(equals(1), equals(2)));
    });
  });

  group('ECN counter updates', () {
    test('ECT(0) increments ect0Counter on ACK', () {
      final conn = _createConnection();
      final ackFrame = AckFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
      );
      final packet = _buildShortHeaderPacket(2, ackFrame.serialize());
      conn.processIncomingDatagram(packet);
      expect(conn.ect0Counter, equals(1));
      expect(conn.ect1Counter, equals(0));
      expect(conn.ceCounter, equals(0));
    });

    test('ECT(1) increments ect1Counter on ACK', () {
      final conn = _createConnection();
      final ackFrame = AckFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
      );
      final packet = _buildShortHeaderPacket(1, ackFrame.serialize());
      conn.processIncomingDatagram(packet);
      expect(conn.ect0Counter, equals(0));
      expect(conn.ect1Counter, equals(1));
      expect(conn.ceCounter, equals(0));
    });

    test('CE increments ceCounter on ACK', () {
      final conn = _createConnection();
      final ackFrame = AckFrame(
        largestAcknowledged: 1,
        ackDelay: 0,
        ackRanges: [],
      );
      final packet = _buildShortHeaderPacket(3, ackFrame.serialize());
      conn.processIncomingDatagram(packet);
      expect(conn.ect0Counter, equals(0));
      expect(conn.ect1Counter, equals(0));
      expect(conn.ceCounter, equals(1));
    });

    test('non-ACK packet does not increment counters', () {
      final conn = _createConnection();
      final pingFrame = PingFrame();
      final packet = _buildShortHeaderPacket(2, pingFrame.serialize());
      conn.processIncomingDatagram(packet);
      expect(conn.ect0Counter, equals(0));
      expect(conn.ect1Counter, equals(0));
      expect(conn.ceCounter, equals(0));
    });
  });

  Set<int> _parseTransportParameterIds(Uint8List tp) {
    final ids = <int>{};
    var offset = 0;
    while (offset < tp.length) {
      final id = VarInt.decode(tp.buffer, offset: tp.offsetInBytes + offset);
      final idLength = VarInt.decodeLength(tp[offset]);
      offset += idLength;
      final length = VarInt.decode(tp.buffer, offset: tp.offsetInBytes + offset);
      final lengthLength = VarInt.decodeLength(tp[offset]);
      offset += lengthLength + length;
      ids.add(id);
    }
    return ids;
  }

  group('Transport parameters', () {
    test('includes max_idle_timeout with default value', () {
      final conn = _createConnection();
      final tp = conn.buildTransportParameters();
      final ids = _parseTransportParameterIds(tp);
      expect(ids, contains(QuicTransportParameterId.maxIdleTimeout.value));
    });

    test('includes max_udp_payload_size with default value', () {
      final conn = _createConnection();
      final tp = conn.buildTransportParameters();
      final ids = _parseTransportParameterIds(tp);
      expect(ids, contains(QuicTransportParameterId.maxUdpPayloadSize.value));
    });

    test('excludes initial_max_data when default is zero', () {
      final conn = _createConnection();
      final tp = conn.buildTransportParameters();
      final ids = _parseTransportParameterIds(tp);
      expect(ids, isNot(contains(QuicTransportParameterId.initialMaxData.value)));
    });

    test('includes ack_delay_exponent and max_ack_delay', () {
      final conn = _createConnection();
      final tp = conn.buildTransportParameters();
      final ids = _parseTransportParameterIds(tp);
      expect(ids, contains(QuicTransportParameterId.ackDelayExponent.value));
      expect(ids, contains(QuicTransportParameterId.maxAckDelay.value));
    });
  });
}

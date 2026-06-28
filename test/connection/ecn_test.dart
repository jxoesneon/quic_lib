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

void main() {
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

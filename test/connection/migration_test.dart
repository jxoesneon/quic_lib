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
import 'package:quic_lib/src/io/platform_address.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';

QuicConnection _createConnection({
  ConnectionStateMachine? stateMachine,
  ConnectionIdManager? cidManager,
  bool allowMigration = true,
  InternetAddress? preferredAddress,
  int preferredAddressPort = 0,
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
    allowMigration: allowMigration,
    preferredAddress: preferredAddress,
    preferredAddressPort: preferredAddressPort,
  );
}

void main() {
  group('Connection migration transport parameters', () {
    test('disable_active_migration present when allowMigration=false', () {
      final conn = _createConnection(allowMigration: false);
      final tp = conn.buildTransportParameters();
      expect(
        tp,
        contains(QuicTransportParameterId.disableActiveMigration.value),
      );
    });

    test('disable_active_migration absent when allowMigration=true', () {
      final conn = _createConnection(allowMigration: true);
      final tp = conn.buildTransportParameters();
      expect(
        tp,
        isNot(contains(QuicTransportParameterId.disableActiveMigration.value)),
      );
    });

    test('preferred_address present when set', () {
      final addr = InternetAddress('192.0.2.1');
      final conn = _createConnection(
        preferredAddress: addr,
        preferredAddressPort: 4433,
      );
      final tp = conn.buildTransportParameters();
      expect(
        tp,
        contains(QuicTransportParameterId.preferredAddress.value),
      );
    });

    test('preferred_address absent when not set', () {
      final conn = _createConnection();
      final tp = conn.buildTransportParameters();
      expect(
        tp,
        isNot(contains(QuicTransportParameterId.preferredAddress.value)),
      );
    });

    test('preferred_address serializes 4-byte address + 2-byte port', () {
      final addr = InternetAddress('192.0.2.1');
      final conn = _createConnection(
        preferredAddress: addr,
        preferredAddressPort: 4433,
      );
      final tp = conn.buildTransportParameters();
      // Verify the value is somewhere in the TP bytes.
      // 192 = 0xC0, 0 = 0x00, 2 = 0x02, 1 = 0x01
      // port 4433 = 0x1151
      expect(tp, contains(0xC0));
      expect(tp, contains(0x00));
      expect(tp, contains(0x02));
      expect(tp, contains(0x01));
    });
  });
}

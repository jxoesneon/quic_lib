import 'dart:isolate';

import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/io/connection_isolate.dart';
import 'package:quic_lib/src/io/isolate_supervisor.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:test/test.dart';

QuicConnection _makeFakeConnection() {
  final rtt = RttEstimator();
  return QuicConnection(
    stateMachine: ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: rtt,
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(rtt),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
  );
}

void main() {
  group('ConnectionIsolate', () {
    test('starts and stops', () {
      final receivePort = ReceivePort();
      final conn = _makeFakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn-1',
      );
      expect(isolate.isRunning, isFalse);
      isolate.start();
      expect(isolate.isRunning, isTrue);
      isolate.stop();
      expect(isolate.isRunning, isFalse);
      receivePort.close();
    });

    test('stores connection and connectionId', () {
      final receivePort = ReceivePort();
      final conn = _makeFakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'test-conn-2',
      );
      expect(isolate.connection, same(conn));
      expect(isolate.connectionId, equals('test-conn-2'));
      receivePort.close();
    });
  });

  group('IsolateSupervisor', () {
    test('registers and unregisters isolates', () {
      final supervisor = IsolateSupervisor();
      final receivePort = ReceivePort();
      final conn = _makeFakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'conn-a',
      );

      expect(supervisor.count, equals(0));
      supervisor.register(isolate);
      expect(supervisor.count, equals(1));
      expect(supervisor.contains('conn-a'), isTrue);

      supervisor.unregister('conn-a');
      expect(supervisor.count, equals(0));
      expect(supervisor.contains('conn-a'), isFalse);
      receivePort.close();
    });

    test('get retrieves registered isolate', () {
      final supervisor = IsolateSupervisor();
      final receivePort = ReceivePort();
      final conn = _makeFakeConnection();
      final isolate = ConnectionIsolate(
        connection: conn,
        sendPort: receivePort.sendPort,
        connectionId: 'conn-b',
      );

      supervisor.register(isolate);
      expect(supervisor.get('conn-b'), same(isolate));
      expect(supervisor.get('nonexistent'), isNull);
      receivePort.close();
    });
  });
}

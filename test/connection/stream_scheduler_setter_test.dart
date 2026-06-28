import 'package:dart_quic/dart_quic.dart';
import 'package:test/test.dart';

void main() {
  group('QuicConnection.streamScheduler setter', () {
    test('setter updates StreamManager.scheduler', () {
      final rtt = RttEstimator();
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: rtt,
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(rtt),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
      );

      final scheduler = RoundRobinScheduler();
      expect(conn.streamManager.scheduler, isNull);

      conn.streamScheduler = scheduler;
      expect(conn.streamManager.scheduler, same(scheduler));
    });

    test('constructor parameter wires scheduler into StreamManager', () {
      final rtt = RttEstimator();
      final scheduler = RoundRobinScheduler();
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: rtt,
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(rtt),
        congestionController: CongestionController(),
        streamIdAllocator: StreamIdAllocator(),
        streamScheduler: scheduler,
      );

      expect(conn.streamManager.scheduler, same(scheduler));
    });
  });
}

import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/recovery_manager.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/recovery/sent_packet_tracker.dart';
import 'package:test/test.dart';

void main() {
  group('RecoveryManager', () {
    late RecoveryManager manager;
    late CongestionController congestion;
    late LossDetector lossDetector;
    late PtoScheduler pto;
    late RttEstimator rtt;
    late SentPacketTracker tracker;

    setUp(() {
      congestion = CongestionController();
      lossDetector = LossDetector();
      rtt = RttEstimator();
      pto = PtoScheduler(rtt);
      tracker = SentPacketTracker();
      manager = RecoveryManager(
        congestionController: congestion,
        lossDetector: lossDetector,
        ptoScheduler: pto,
        rttEstimator: rtt,
        sentPacketTracker: tracker,
      );
    });

    test('onAckReceived updates all subsystems', () {
      manager.onPacketSent(0, 1, 1000, 100, ackEliciting: true, inFlight: true);
      manager.onAckReceived(0, 1, 2000, 100);
      expect(congestion.bytesInFlight, equals(0));
    });

    test('onAckReceived with computed acked bytes', () {
      manager.onPacketSent(0, 1, 1000, 100, ackEliciting: true, inFlight: true);
      manager.onAckReceived(
          0, 1, 2000, 0); // ackedBytes=0 triggers computed path
      expect(congestion.bytesInFlight, equals(0));
    });

    test('onAckReceived with loss triggers congestion event', () {
      manager.onPacketSent(0, 1, 1000, 100);
      manager.onPacketSent(0, 2, 1001, 100);
      manager.onPacketSent(0, 10, 2000, 100);
      // ACK only packet 10 with a large delay to trigger loss on 1,2
      manager.onAckReceived(0, 10, 1000000, 300);
      expect(congestion.bytesInFlight, equals(0));
    });

    test('onPacketSent tracks packet with default parameters', () {
      manager.onPacketSent(0, 1, 1000, 100);
      expect(tracker.getUnackedPackets(0).length, equals(1));
    });

    test('onPacketSent tracks non-ack-eliciting packet', () {
      manager.onPacketSent(0, 1, 1000, 100,
          ackEliciting: false, inFlight: true);
      expect(tracker.getUnackedPackets(0).length, equals(1));
    });

    test('isPtoExpired returns false when timer not armed', () {
      expect(manager.isPtoExpired(1001), isFalse);
    });

    test('onPtoFired increments pto count', () {
      manager.onPtoFired(1000000);
      expect(manager.ptoScheduler.ptoCount, greaterThan(0));
    });

    test('reset clears all subsystems', () {
      manager.onPacketSent(0, 1, 1000, 100);
      manager.reset();
      expect(tracker.getUnackedPackets(0).length, equals(0));
      expect(congestion.bytesInFlight, equals(0));
    });

    test('convenience getters return subsystems', () {
      expect(manager.congestionController, same(congestion));
      expect(manager.lossDetector, same(lossDetector));
      expect(manager.ptoScheduler, same(pto));
      expect(manager.rttEstimator, same(rtt));
      expect(manager.sentPacketTracker, same(tracker));
    });
  });
}

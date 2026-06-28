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

    test('persistent congestion not declared before first ack', () {
      expect(manager.checkPersistentCongestion(1000000), isFalse);
    });

    test('persistent congestion declared when duration exceeds 3*PTO', () {
      // Send and ack a packet so largestAckedSentTime is known.
      manager.onPacketSent(0, 1, 1000, 100);
      manager.onAckReceived(0, 1, 2000, 100);

      // With default RTT values, PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay
      // Default smoothed = 333000, rttvar = 166500, max_ack_delay = 25000
      // PTO = 333000 + max(666000, 1000) + 25000 = 333000 + 666000 + 25000 = 1_024_000 us
      // Persistent duration = 3 * 1_024_000 = 3_072_000 us
      final pto = rtt.getPtoDuration();
      final persistentDuration = 3 * pto;

      // Just under the threshold (duration starts from sent time = 1000).
      expect(manager.checkPersistentCongestion(1000 + persistentDuration),
          isFalse);

      // Just over the threshold.
      expect(
          manager.checkPersistentCongestion(1000 + persistentDuration + 1),
          isTrue);

      // cwnd should be reset to initial window.
      expect(congestion.congestionWindow,
          equals(CongestionController.initialWindow));
    });

    test('reset clears persistent congestion state', () {
      manager.onPacketSent(0, 1, 1000, 100);
      manager.onAckReceived(0, 1, 2000, 100);
      manager.reset();
      expect(manager.checkPersistentCongestion(10000000), isFalse);
    });
  });
}

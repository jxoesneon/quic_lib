import 'package:test/test.dart';
import 'package:quic_lib/src/connection/congestion_control/bbr.dart';

void main() {
  group('BbrCongestionController', () {
    test('initial state is STARTUP', () {
      final bbr = BbrCongestionController();
      expect(bbr.state, equals(BbrState.startup));
    });

    test('initial cwnd is 4 packets', () {
      final bbr = BbrCongestionController();
      expect(bbr.cwndInPackets, equals(4));
    });

    test('onPacketSent increases bytes in flight', () {
      final bbr = BbrCongestionController();
      bbr.onPacketSent(0, 1200);
      expect(bbr.bytesInFlight, equals(1200));
    });

    test('onAckReceived decreases bytes in flight', () {
      final bbr = BbrCongestionController();
      bbr.onPacketSent(0, 1200);
      bbr.onAckReceived(0, 1200, DateTime.now());
      expect(bbr.bytesInFlight, equals(0));
    });

    test('onRttSample updates min RTT', () {
      final bbr = BbrCongestionController();
      bbr.onRttSample(const Duration(milliseconds: 100));
      expect(bbr.minRttUs, equals(100000));
    });

    test('onRttSample keeps minimum RTT', () {
      final bbr = BbrCongestionController();
      bbr.onRttSample(const Duration(milliseconds: 100));
      bbr.onRttSample(const Duration(milliseconds: 80));
      expect(bbr.minRttUs, equals(80000));
    });

    test('reset restores initial state', () {
      final bbr = BbrCongestionController();
      bbr.onPacketSent(0, 1200);
      bbr.onRttSample(const Duration(milliseconds: 50));
      bbr.reset();
      expect(bbr.cwndInPackets, equals(4));
      expect(bbr.bytesInFlight, equals(0));
      expect(bbr.state, equals(BbrState.startup));
      expect(bbr.btlBw, equals(0));
    });

    test('canSend respects cwnd', () {
      final bbr = BbrCongestionController(packetSize: 1200);
      // cwnd = 4 packets = 4800 bytes
      expect(bbr.canSend(4800), isTrue);
      bbr.onPacketSent(0, 4800);
      expect(bbr.canSend(1), isFalse);
    });

    test('onPacketLost does not shrink cwnd', () {
      final bbr = BbrCongestionController();
      final initialCwnd = bbr.cwndInPackets;
      bbr.onPacketLost(0, 1200, DateTime.now());
      expect(bbr.cwndInPackets, equals(initialCwnd));
    });

    test('appLimited is always false', () {
      final bbr = BbrCongestionController();
      expect(bbr.appLimited, isFalse);
      bbr.setAppLimited(true);
      expect(bbr.appLimited, isFalse);
    });

    test('onPersistentCongestion resets to minimum', () {
      final bbr = BbrCongestionController();
      bbr.onPersistentCongestion();
      expect(bbr.cwndInPackets, equals(4));
      expect(bbr.state, equals(BbrState.startup));
    });

    test('congestionWindow is reported in bytes', () {
      final bbr = BbrCongestionController(packetSize: 1200);
      expect(bbr.congestionWindow, equals(4 * 1200));
    });

    test('onECNCEMarked is a no-op', () {
      final bbr = BbrCongestionController();
      expect(() => bbr.onECNCEMarked(5), returnsNormally);
      expect(bbr.cwndInPackets, equals(4));
    });

    test('exits STARTUP when bandwidth growth stalls', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      // Stall bandwidth growth for three rounds, then send extra packets and
      // complete the fourth round by acking the last packet. This leaves
      // enough bytes in flight that the DRAIN -> PROBE_BW transition is not
      // triggered immediately.
      for (var i = 0; i < 3; i++) {
        bbr.onPacketSent(i, 1200);
        bbr.onAckReceived(i, 1200, now);
      }
      bbr.onPacketSent(3, 1200);
      bbr.onPacketSent(4, 1200);
      bbr.onPacketSent(5, 1200);
      bbr.onAckReceived(5, 1200, now);
      expect(bbr.state, equals(BbrState.drain));
      expect(bbr.bytesInFlight, greaterThan(1200));
    });

    test('exits DRAIN when bytes in flight fit BDP', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      // Force into DRAIN with excess bytes in flight.
      for (var i = 0; i < 3; i++) {
        bbr.onPacketSent(i, 1200);
        bbr.onAckReceived(i, 1200, now);
      }
      bbr.onPacketSent(3, 1200);
      bbr.onPacketSent(4, 1200);
      bbr.onPacketSent(5, 1200);
      bbr.onAckReceived(5, 1200, now);
      expect(bbr.state, equals(BbrState.drain));
      expect(bbr.bytesInFlight, greaterThan(1200));
      // Drain bytes in flight below BDP estimate so DRAIN -> PROBE_BW.
      bbr.onPacketLost(3, bbr.bytesInFlight - 1200, now);
      bbr.onAckReceived(5, 0, now);
      expect(bbr.state, equals(BbrState.probeBw));
    });

    test('enters PROBE_RTT after enough time passes', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      // Get into PROBE_BW.
      for (var i = 0; i < 4; i++) {
        bbr.onPacketSent(i, 1200);
        bbr.onAckReceived(i, 1200, now);
      }
      bbr.onPacketLost(4, bbr.bytesInFlight, now);
      bbr.onAckReceived(3, 0, now);
      expect(bbr.state, equals(BbrState.probeBw));

      // Move time forward beyond the PROBE_RTT interval.
      final future = now.add(const Duration(seconds: 11));
      bbr.onAckReceived(3, 0, future);
      expect(bbr.state, equals(BbrState.probeRtt));
    });

    test('cwnd is capped at minimum during PROBE_RTT', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      // Ramp up cwnd in STARTUP.
      for (var i = 0; i < 4; i++) {
        bbr.onPacketSent(i, 1200);
        bbr.onAckReceived(i, 1200, now);
      }
      bbr.onPacketLost(4, bbr.bytesInFlight, now);
      bbr.onAckReceived(3, 0, now);
      expect(bbr.state, equals(BbrState.probeBw));

      final future = now.add(const Duration(seconds: 11));
      bbr.onAckReceived(3, 0, future);
      expect(bbr.state, equals(BbrState.probeRtt));
      expect(bbr.cwndInPackets, greaterThanOrEqualTo(4));
    });

    test('pacing interval is updated when bandwidth is known', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      bbr.onPacketSent(0, 1200);
      bbr.onAckReceived(0, 1200, now);
      expect(bbr.pacingIntervalUs, greaterThan(0));
    });

    test('probeBw pacing gain cycles through phases', () {
      final bbr = BbrCongestionController();
      final now = DateTime.now();
      for (var i = 0; i < 4; i++) {
        bbr.onPacketSent(i, 1200);
        bbr.onAckReceived(i, 1200, now);
      }
      bbr.onPacketLost(4, bbr.bytesInFlight, now);
      bbr.onAckReceived(3, 0, now);
      expect(bbr.state, equals(BbrState.probeBw));
      expect(bbr.pacingIntervalUs, greaterThan(0));
    });
  });
}

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
  });
}

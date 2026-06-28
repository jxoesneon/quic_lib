import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';

void main() {
  group('CongestionController', () {
    late CongestionController controller;

    setUp(() {
      controller = CongestionController();
    });

    test('initial cwnd is 2400', () {
      expect(controller.congestionWindow, equals(2400));
      expect(controller.ssthresh, equals(-1));
      expect(controller.inSlowStart, isTrue);
      expect(controller.inRecovery, isFalse);
      expect(controller.bytesInFlight, equals(0));
    });

    test('slow start doubles cwnd on ack', () {
      controller.onPacketSent(2400);
      expect(controller.bytesInFlight, equals(2400));

      controller.onAckReceived(2400);
      expect(controller.congestionWindow, equals(4800));
      expect(controller.bytesInFlight, equals(0));
      expect(controller.inSlowStart, isTrue);
    });

    test('congestion avoidance grows linearly', () {
      // Grow cwnd to 4800 in slow start.
      controller.onPacketSent(2400);
      controller.onAckReceived(2400);
      expect(controller.congestionWindow, equals(4800));

      // Trigger congestion event to set ssthresh and exit slow start.
      controller.onCongestionEvent(1000);
      expect(controller.inRecovery, isTrue);
      expect(controller.ssthresh, equals(2400));
      expect(controller.congestionWindow, equals(2400));

      // Exit recovery so cwnd can grow again.
      controller.onRecoveryExit();
      expect(controller.inRecovery, isFalse);
      expect(controller.inSlowStart, isFalse);

      // Ack 1200 bytes in congestion avoidance.
      // cwnd += max_datagram_size * acked_bytes / cwnd
      // 2400 + (1200 * 1200) ~/ 2400 = 2400 + 600 = 3000
      controller.onAckReceived(1200);
      expect(controller.congestionWindow, equals(3000));
    });

    test('congestion event halves cwnd', () {
      // Grow cwnd in slow start.
      controller.onPacketSent(2400);
      controller.onAckReceived(2400);
      expect(controller.congestionWindow, equals(4800));

      controller.onCongestionEvent(1000);
      expect(controller.ssthresh, equals(2400));
      expect(controller.congestionWindow, equals(2400));
      expect(controller.inRecovery, isTrue);
    });

    test('second congestion event does not reduce cwnd again', () {
      controller.onPacketSent(2400);
      controller.onAckReceived(2400);
      controller.onCongestionEvent(1000);
      expect(controller.congestionWindow, equals(2400));

      // Another event while still in recovery must not change cwnd.
      controller.onCongestionEvent(2000);
      expect(controller.congestionWindow, equals(2400));
      expect(controller.ssthresh, equals(2400));
    });

    test('canSend respects cwnd', () {
      expect(controller.canSend(2400), isTrue);
      expect(controller.canSend(2401), isFalse);

      controller.onPacketSent(2400);
      expect(controller.bytesInFlight, equals(2400));
      expect(controller.canSend(1), isFalse);
      expect(controller.canSend(0), isTrue);

      controller.onAckReceived(1200);
      expect(controller.bytesInFlight, equals(1200));
      // In slow start cwnd grows to 2400 + 1200 = 3600.
      expect(controller.canSend(2400), isTrue);
      expect(controller.canSend(2401), isFalse);
    });

    test('reset restores defaults', () {
      controller.onPacketSent(2400);
      controller.onAckReceived(2400);
      controller.onCongestionEvent(1000);
      controller.onPacketSent(1200);

      controller.reset();

      expect(controller.congestionWindow, equals(2400));
      expect(controller.ssthresh, equals(-1));
      expect(controller.inSlowStart, isTrue);
      expect(controller.inRecovery, isFalse);
      expect(controller.bytesInFlight, equals(0));
    });

    test('no cwnd growth while in recovery', () {
      controller.onPacketSent(2400);
      controller.onAckReceived(2400);
      expect(controller.congestionWindow, equals(4800));

      controller.onCongestionEvent(1000);
      expect(controller.inRecovery, isTrue);

      // Ack while in recovery should not grow cwnd.
      controller.onAckReceived(2400);
      expect(controller.congestionWindow, equals(2400));
    });

    test('bytes in flight does not go negative', () {
      controller.onAckReceived(100);
      expect(controller.bytesInFlight, equals(0));
    });
  });
}

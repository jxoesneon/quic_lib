import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/ack_generator.dart';

void main() {
  group('AckGenerator', () {
    test('initial state', () {
      final ag = AckGenerator();
      expect(ag.largestAcked, equals(-1));
    });

    test('onPacketReceived updates largestAcked', () {
      final ag = AckGenerator();
      ag.onPacketReceived(5, 0);
      expect(ag.largestAcked, equals(5));
    });

    test('buildAckFrame contains correct largestAcked', () {
      final ag = AckGenerator();
      ag.onPacketReceived(10, 0);
      final frame = ag.buildAckFrame();
      expect(frame.largestAcknowledged, equals(10));
    });

    test('reset clears state', () {
      final ag = AckGenerator();
      ag.onPacketReceived(5, 0);
      ag.reset();
      expect(ag.largestAcked, equals(-1));
    });
  });
}

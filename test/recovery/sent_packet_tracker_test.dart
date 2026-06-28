import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/sent_packet_tracker.dart';

void main() {
  group('SentPacketTracker', () {
    test('tracks sent packets', () {
      final tracker = SentPacketTracker();
      tracker.track(SentPacketInfo(
        packetNumber: 0,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [0x01],
        space: 2,
      ));
      expect(tracker.getUnackedPackets(2).length, equals(1));
    });

    test('ACK removes tracked packets', () {
      final tracker = SentPacketTracker();
      tracker.track(SentPacketInfo(
        packetNumber: 0,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [0x01],
        space: 2,
      ));
      final acked = tracker.onAck(2, 0, []);
      expect(acked.length, equals(1));
      expect(tracker.getUnackedPackets(2).length, equals(0));
    });

    test('largestAcked tracked', () {
      final tracker = SentPacketTracker();
      tracker.track(SentPacketInfo(
        packetNumber: 5,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [0x01],
        space: 2,
      ));
      tracker.onAck(2, 5, []);
      expect(tracker.getLargestAcked(2), equals(5));
    });

    test('proper ACK range parsing removes only ranged packets', () {
      final tracker = SentPacketTracker();
      for (var i = 0; i < 5; i++) {
        tracker.track(SentPacketInfo(
          packetNumber: i,
          sentTimeUs: 0,
          sizeInBytes: 100,
          frames: [0x01],
          space: 2,
        ));
      }
      // ACK largest=4, first range: gap=0, length=1 (acks packets 3-4).
      // Then gap=1, length=0 (acks packet 2).
      final acked = tracker.onAck(2, 4, [
        (gap: 0, length: 1),
        (gap: 1, length: 0),
      ]);
      expect(acked.length, equals(3)); // packets 2, 3, 4
      final unacked = tracker.getUnackedPackets(2);
      expect(unacked.length, equals(2)); // packets 0, 1
    });

    test('reset clears state', () {
      final tracker = SentPacketTracker();
      tracker.track(SentPacketInfo(
        packetNumber: 0,
        sentTimeUs: 0,
        sizeInBytes: 100,
        frames: [0x01],
        space: 2,
      ));
      tracker.reset(2);
      expect(tracker.getUnackedPackets(2).length, equals(0));
    });
  });
}

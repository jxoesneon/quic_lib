import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';

void main() {
  group('PacketNumberSpaceManager', () {
    test('initial packet numbers are 0', () {
      final manager = PacketNumberSpaceManager();
      expect(manager.peek(PacketNumberSpace.initial), equals(0));
      expect(manager.peek(PacketNumberSpace.handshake), equals(0));
      expect(manager.peek(PacketNumberSpace.application), equals(0));
    });

    test('allocate increments per space', () {
      final manager = PacketNumberSpaceManager();
      expect(manager.allocate(PacketNumberSpace.initial), equals(0));
      expect(manager.allocate(PacketNumberSpace.initial), equals(1));
      expect(manager.allocate(PacketNumberSpace.initial), equals(2));
    });

    test('allocate independent across spaces', () {
      final manager = PacketNumberSpaceManager();
      expect(manager.allocate(PacketNumberSpace.initial), equals(0));
      expect(manager.allocate(PacketNumberSpace.handshake), equals(0));
      expect(manager.allocate(PacketNumberSpace.application), equals(0));

      expect(manager.allocate(PacketNumberSpace.initial), equals(1));
      expect(manager.allocate(PacketNumberSpace.handshake), equals(1));
      expect(manager.allocate(PacketNumberSpace.application), equals(1));
    });

    test('onAck updates largestAcked', () {
      final manager = PacketNumberSpaceManager();
      expect(manager.largestAcked(PacketNumberSpace.initial), equals(-1));

      manager.onAck(PacketNumberSpace.initial, 5);
      expect(manager.largestAcked(PacketNumberSpace.initial), equals(5));

      manager.onAck(PacketNumberSpace.initial, 3);
      expect(manager.largestAcked(PacketNumberSpace.initial), equals(5));

      manager.onAck(PacketNumberSpace.initial, 7);
      expect(manager.largestAcked(PacketNumberSpace.initial), equals(7));
    });

    test('onReceived updates largestReceived and rejects replays', () {
      final manager = PacketNumberSpaceManager();
      expect(manager.largestReceived(PacketNumberSpace.initial), equals(-1));

      // Start from packet 0 (realistic first packet).
      expect(manager.onReceived(PacketNumberSpace.initial, 0), isTrue);
      expect(manager.largestReceived(PacketNumberSpace.initial), equals(0));

      // Out-of-order packet 2 within window: accepted.
      expect(manager.onReceived(PacketNumberSpace.initial, 2), isTrue);
      expect(manager.largestReceived(PacketNumberSpace.initial), equals(2));

      // Replay of packet 0: rejected (already in window).
      expect(manager.onReceived(PacketNumberSpace.initial, 0), isFalse);

      // Replay of packet 2: rejected.
      expect(manager.onReceived(PacketNumberSpace.initial, 2), isFalse);

      // Advance far beyond window (64 packets ahead).
      expect(manager.onReceived(PacketNumberSpace.initial, 65), isTrue);
      expect(manager.largestReceived(PacketNumberSpace.initial), equals(65));

      // Packet 0 is now outside the replay window: rejected.
      expect(manager.onReceived(PacketNumberSpace.initial, 0), isFalse);

      // Packet 64 is within new window and not yet seen: accepted.
      expect(manager.onReceived(PacketNumberSpace.initial, 64), isTrue);
    });

    test('reset clears a space', () {
      final manager = PacketNumberSpaceManager();
      manager.allocate(PacketNumberSpace.initial);
      manager.allocate(PacketNumberSpace.initial);
      manager.onAck(PacketNumberSpace.initial, 3);
      manager.onReceived(PacketNumberSpace.initial, 4);

      manager.reset(PacketNumberSpace.initial);

      expect(manager.peek(PacketNumberSpace.initial), equals(0));
      expect(manager.largestAcked(PacketNumberSpace.initial), equals(-1));
      expect(manager.largestReceived(PacketNumberSpace.initial), equals(-1));
    });

    test('resetAll clears all spaces', () {
      final manager = PacketNumberSpaceManager();
      manager.allocate(PacketNumberSpace.initial);
      manager.allocate(PacketNumberSpace.handshake);
      manager.allocate(PacketNumberSpace.application);
      manager.onAck(PacketNumberSpace.initial, 1);
      manager.onReceived(PacketNumberSpace.handshake, 2);

      manager.resetAll();

      for (final space in PacketNumberSpace.values) {
        expect(manager.peek(space), equals(0));
        expect(manager.largestAcked(space), equals(-1));
        expect(manager.largestReceived(space), equals(-1));
      }
    });
  });
}

import 'package:dart_quic/src/libp2p/peer_id.dart';
import 'package:test/test.dart';

void main() {
  group('PeerId', () {
    test('fromBytes stores bytes correctly', () {
      final raw = <int>[0x00, 0x0f, 0x12, 0xab, 0xff];
      final peerId = PeerId.fromBytes(raw);
      expect(peerId.bytes, orderedEquals(raw));
    });

    test('equality works for same bytes', () {
      final a = PeerId.fromBytes(<int>[1, 2, 3]);
      final b = PeerId.fromBytes(<int>[1, 2, 3]);
      expect(a, equals(b));
      expect(a == b, isTrue);
    });

    test('inequality works for different bytes', () {
      final a = PeerId.fromBytes(<int>[1, 2, 3]);
      final b = PeerId.fromBytes(<int>[1, 2, 4]);
      expect(a, isNot(equals(b)));
      expect(a == b, isFalse);
    });

    test('toString returns hex representation', () {
      final peerId = PeerId.fromBytes(<int>[0x00, 0x0f, 0x12, 0xab, 0xff]);
      expect(peerId.toString(), equals('000f12abff'));
    });

    test('hashCode is consistent with equality', () {
      final a = PeerId.fromBytes(<int>[10, 20, 30]);
      final b = PeerId.fromBytes(<int>[10, 20, 30]);
      expect(a.hashCode, equals(b.hashCode));
    });
  });
}

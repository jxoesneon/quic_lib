import 'package:dart_quic/src/libp2p/peer_id.dart';
import 'package:test/test.dart';

void main() {
  group('PeerId wired encoding methods', () {
    test('fromBase58 round-trips with toBase58', () {
      final peer = PeerId.fromBytes(<int>[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      final encoded = peer.toBase58();
      final decoded = PeerId.fromBase58(encoded);
      expect(decoded.bytes, orderedEquals(peer.bytes));
    });

    test('fromBase58 throws for invalid characters', () {
      expect(
        () => PeerId.fromBase58('0OIl'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('toBase36 produces lowercase output', () {
      final peer = PeerId.fromBytes(<int>[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
      final encoded = peer.toBase36();
      expect(encoded, equals(peer.encodeBase36()));
      expect(encoded, equals(encoded.toLowerCase()));
    });
  });
}

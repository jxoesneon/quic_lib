import 'package:dart_quic/src/streams/stream_id.dart';
import 'package:test/test.dart';

void main() {
  group('StreamId', () {
    test('encode/decode round-trip for all 4 types', () {
      final types = [
        StreamId.typeClientBidi,
        StreamId.typeServerBidi,
        StreamId.typeClientUni,
        StreamId.typeServerUni,
      ];

      for (final type in types) {
        for (final sequence in [0, 1, 5, 100, 999999]) {
          final id = StreamId.encode(type: type, sequence: sequence);
          final decoded = StreamId.decode(id);
          expect(decoded.type, equals(type),
              reason: 'type mismatch for type=$type, sequence=$sequence');
          expect(decoded.sequence, equals(sequence),
              reason: 'sequence mismatch for type=$type, sequence=$sequence');
        }
      }
    });

    test('first few stream IDs match RFC examples', () {
      // Client bidi: 0, 4, 8, 12, …
      expect(StreamId.encode(type: StreamId.typeClientBidi, sequence: 0), 0);
      expect(StreamId.encode(type: StreamId.typeClientBidi, sequence: 1), 4);
      expect(StreamId.encode(type: StreamId.typeClientBidi, sequence: 2), 8);
      expect(StreamId.encode(type: StreamId.typeClientBidi, sequence: 3), 12);

      // Server bidi: 1, 5, 9, 13, …
      expect(StreamId.encode(type: StreamId.typeServerBidi, sequence: 0), 1);
      expect(StreamId.encode(type: StreamId.typeServerBidi, sequence: 1), 5);
      expect(StreamId.encode(type: StreamId.typeServerBidi, sequence: 2), 9);
      expect(StreamId.encode(type: StreamId.typeServerBidi, sequence: 3), 13);

      // Client uni: 2, 6, 10, 14, …
      expect(StreamId.encode(type: StreamId.typeClientUni, sequence: 0), 2);
      expect(StreamId.encode(type: StreamId.typeClientUni, sequence: 1), 6);
      expect(StreamId.encode(type: StreamId.typeClientUni, sequence: 2), 10);
      expect(StreamId.encode(type: StreamId.typeClientUni, sequence: 3), 14);

      // Server uni: 3, 7, 11, 15, …
      expect(StreamId.encode(type: StreamId.typeServerUni, sequence: 0), 3);
      expect(StreamId.encode(type: StreamId.typeServerUni, sequence: 1), 7);
      expect(StreamId.encode(type: StreamId.typeServerUni, sequence: 2), 11);
      expect(StreamId.encode(type: StreamId.typeServerUni, sequence: 3), 15);
    });

    test('isClientInitiated correctness', () {
      // Client bidi (0) and client uni (2) are client-initiated.
      expect(StreamId.isClientInitiated(0), isTrue);
      expect(StreamId.isClientInitiated(4), isTrue);
      expect(StreamId.isClientInitiated(2), isTrue);
      expect(StreamId.isClientInitiated(6), isTrue);

      // Server bidi (1) and server uni (3) are not client-initiated.
      expect(StreamId.isClientInitiated(1), isFalse);
      expect(StreamId.isClientInitiated(5), isFalse);
      expect(StreamId.isClientInitiated(3), isFalse);
      expect(StreamId.isClientInitiated(7), isFalse);
    });

    test('isServerInitiated correctness', () {
      expect(StreamId.isServerInitiated(1), isTrue);
      expect(StreamId.isServerInitiated(5), isTrue);
      expect(StreamId.isServerInitiated(3), isTrue);
      expect(StreamId.isServerInitiated(7), isTrue);

      expect(StreamId.isServerInitiated(0), isFalse);
      expect(StreamId.isServerInitiated(4), isFalse);
      expect(StreamId.isServerInitiated(2), isFalse);
      expect(StreamId.isServerInitiated(6), isFalse);
    });

    test('isBidirectional correctness', () {
      // Client bidi (0) and server bidi (1) are bidirectional.
      expect(StreamId.isBidirectional(0), isTrue);
      expect(StreamId.isBidirectional(1), isTrue);
      expect(StreamId.isBidirectional(4), isTrue);
      expect(StreamId.isBidirectional(5), isTrue);

      // Client uni (2) and server uni (3) are not bidirectional.
      expect(StreamId.isBidirectional(2), isFalse);
      expect(StreamId.isBidirectional(3), isFalse);
      expect(StreamId.isBidirectional(6), isFalse);
      expect(StreamId.isBidirectional(7), isFalse);
    });

    test('isUnidirectional correctness', () {
      expect(StreamId.isUnidirectional(2), isTrue);
      expect(StreamId.isUnidirectional(3), isTrue);
      expect(StreamId.isUnidirectional(6), isTrue);
      expect(StreamId.isUnidirectional(7), isTrue);

      expect(StreamId.isUnidirectional(0), isFalse);
      expect(StreamId.isUnidirectional(1), isFalse);
      expect(StreamId.isUnidirectional(4), isFalse);
      expect(StreamId.isUnidirectional(5), isFalse);
    });

    test('typeBits and sequence correctness', () {
      // typeBits extracts bottom 2 bits.
      expect(StreamId.typeBits(0), 0);
      expect(StreamId.typeBits(1), 1);
      expect(StreamId.typeBits(2), 2);
      expect(StreamId.typeBits(3), 3);
      expect(StreamId.typeBits(4), 0);
      expect(StreamId.typeBits(5), 1);
      expect(StreamId.typeBits(6), 2);
      expect(StreamId.typeBits(7), 3);

      // sequence extracts the upper bits (>> 2).
      expect(StreamId.sequence(0), 0);
      expect(StreamId.sequence(4), 1);
      expect(StreamId.sequence(8), 2);
      expect(StreamId.sequence(1), 0);
      expect(StreamId.sequence(5), 1);
      expect(StreamId.sequence(9), 2);
      expect(StreamId.sequence(2), 0);
      expect(StreamId.sequence(6), 1);
      expect(StreamId.sequence(10), 2);
      expect(StreamId.sequence(3), 0);
      expect(StreamId.sequence(7), 1);
      expect(StreamId.sequence(11), 2);
    });
  });

  group('StreamIdAllocator', () {
    test('produces correct sequences', () {
      final allocator = StreamIdAllocator();

      // First allocation for each category should yield the base IDs.
      expect(allocator.allocateClientBidi(), 0);
      expect(allocator.allocateServerBidi(), 1);
      expect(allocator.allocateClientUni(), 2);
      expect(allocator.allocateServerUni(), 3);

      // Second allocation increments by 4.
      expect(allocator.allocateClientBidi(), 4);
      expect(allocator.allocateServerBidi(), 5);
      expect(allocator.allocateClientUni(), 6);
      expect(allocator.allocateServerUni(), 7);

      // Third allocation.
      expect(allocator.allocateClientBidi(), 8);
      expect(allocator.allocateServerBidi(), 9);
      expect(allocator.allocateClientUni(), 10);
      expect(allocator.allocateServerUni(), 11);
    });

    test('categories are independent', () {
      final allocator = StreamIdAllocator();

      // Allocate several client-bidi IDs.
      expect(allocator.allocateClientBidi(), 0);
      expect(allocator.allocateClientBidi(), 4);
      expect(allocator.allocateClientBidi(), 8);

      // Server-bidi counter should still be at zero.
      expect(allocator.allocateServerBidi(), 1);
      expect(allocator.allocateServerBidi(), 5);
    });

    test('maxStreamId constant is 2^62 - 1', () {
      expect(StreamIdAllocator.maxStreamId, equals(4611686018427387903));
    });
  });
}

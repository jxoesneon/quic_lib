import 'dart:typed_data';

import 'package:quic_lib/src/wire/quic_bit_greaser.dart';
import 'package:test/test.dart';

void main() {
  group('QuicBitGreaser', () {
    test('greasePacket sets bit 6', () {
      final packet = Uint8List.fromList([0x00, 0x01, 0x02]);
      final greased = QuicBitGreaser.greasePacket(packet);
      expect(QuicBitGreaser.isQuicBitSet(greased), isTrue);
      expect(greased[0], equals(0x40));
      // Remaining bytes unchanged.
      expect(greased[1], equals(0x01));
      expect(greased[2], equals(0x02));
    });

    test('ungreasePacket clears bit 6', () {
      final packet = Uint8List.fromList([0xFF, 0x01, 0x02]);
      final ungreased = QuicBitGreaser.ungreasePacket(packet);
      expect(QuicBitGreaser.isQuicBitSet(ungreased), isFalse);
      expect(ungreased[0], equals(0xBF));
      // Remaining bytes unchanged.
      expect(ungreased[1], equals(0x01));
      expect(ungreased[2], equals(0x02));
    });

    test('randomizeQuicBit statistical distribution', () {
      var setCount = 0;
      const iterations = 100;
      for (var i = 0; i < iterations; i++) {
        final packet = Uint8List.fromList([0x00]);
        final result = QuicBitGreaser.randomizeQuicBit(packet);
        if (QuicBitGreaser.isQuicBitSet(result)) {
          setCount++;
        }
      }
      // With 100 iterations, expect roughly 50% set.
      // Allow a generous margin (30..70) to avoid flaky tests.
      expect(setCount, greaterThan(20));
      expect(setCount, lessThan(80));
    });

    test('isQuicBitSet returns false for empty packet', () {
      expect(QuicBitGreaser.isQuicBitSet(Uint8List(0)), isFalse);
    });

    test('isQuicBitSet returns true when bit 6 is set', () {
      expect(QuicBitGreaser.isQuicBitSet(Uint8List.fromList([0x40])), isTrue);
      expect(QuicBitGreaser.isQuicBitSet(Uint8List.fromList([0x7F])), isTrue);
    });

    test('isQuicBitSet returns false when bit 6 is clear', () {
      expect(QuicBitGreaser.isQuicBitSet(Uint8List.fromList([0x00])), isFalse);
      expect(QuicBitGreaser.isQuicBitSet(Uint8List.fromList([0xBF])), isFalse);
    });

    test('greasePacket returns empty packet unchanged', () {
      final empty = Uint8List(0);
      expect(QuicBitGreaser.greasePacket(empty), equals(empty));
    });

    test('ungreasePacket returns empty packet unchanged', () {
      final empty = Uint8List(0);
      expect(QuicBitGreaser.ungreasePacket(empty), equals(empty));
    });

    test('randomizeQuicBit returns empty packet unchanged', () {
      final empty = Uint8List(0);
      expect(QuicBitGreaser.randomizeQuicBit(empty), equals(empty));
    });
  });
}

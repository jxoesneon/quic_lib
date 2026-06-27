import 'dart:typed_data';

import 'package:dart_quic/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  late CryptoFrameAssembler assembler;

  setUp(() {
    assembler = CryptoFrameAssembler();
  });

  group('CryptoFrameAssembler', () {
    test('single frame delivered immediately', () {
      final frame = CryptoFrame(offset: 0, data: [1, 2, 3]);
      final result = assembler.deliver(frame);

      expect(result.length, equals(1));
      expect(result[0], equals(Uint8List.fromList([1, 2, 3])));
      expect(assembler.nextOffset, equals(3));
      expect(assembler.hasGaps, isFalse);
    });

    test('out-of-order frames assembled correctly', () {
      final frame2 = CryptoFrame(offset: 3, data: [4, 5, 6]);
      final result1 = assembler.deliver(frame2);

      expect(result1, isEmpty);
      expect(assembler.nextOffset, equals(0));
      expect(assembler.hasGaps, isTrue);

      final frame1 = CryptoFrame(offset: 0, data: [1, 2, 3]);
      final result2 = assembler.deliver(frame1);

      expect(result2.length, equals(1));
      expect(result2[0], equals(Uint8List.fromList([1, 2, 3, 4, 5, 6])));
      expect(assembler.nextOffset, equals(6));
      expect(assembler.hasGaps, isFalse);
    });

    test('gap prevents delivery until filled', () {
      final frame1 = CryptoFrame(offset: 0, data: [1, 2, 3]);
      final result1 = assembler.deliver(frame1);

      expect(result1.length, equals(1));
      expect(assembler.nextOffset, equals(3));

      final frame3 = CryptoFrame(offset: 6, data: [7, 8, 9]);
      final result2 = assembler.deliver(frame3);

      expect(result2, isEmpty);
      expect(assembler.nextOffset, equals(3));
      expect(assembler.hasGaps, isTrue);

      // Fill the gap
      final frame2 = CryptoFrame(offset: 3, data: [4, 5, 6]);
      final result3 = assembler.deliver(frame2);

      expect(result3.length, equals(1));
      expect(result3[0], equals(Uint8List.fromList([4, 5, 6, 7, 8, 9])));
      expect(assembler.nextOffset, equals(9));
      expect(assembler.hasGaps, isFalse);
    });

    test('reset clears state', () {
      final frame = CryptoFrame(offset: 0, data: [1, 2, 3]);
      assembler.deliver(frame);
      expect(assembler.nextOffset, equals(3));
      expect(assembler.hasGaps, isFalse);

      assembler.reset();
      expect(assembler.nextOffset, equals(0));
      expect(assembler.hasGaps, isFalse);

      // After reset we can receive from the start again
      final frame2 = CryptoFrame(offset: 5, data: [6, 7, 8]);
      final result = assembler.deliver(frame2);

      expect(result, isEmpty);
      expect(assembler.nextOffset, equals(0));
      expect(assembler.hasGaps, isTrue);
    });
  });
}

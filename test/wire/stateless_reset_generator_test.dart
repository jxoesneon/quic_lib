import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/wire/stateless_reset_generator.dart';

void main() {
  group('StatelessResetGenerator', () {
    test('generate produces packet >= minPacketSize', () {
      final token = List<int>.filled(16, 0xAA);
      final packet =
          StatelessResetGenerator.generate(token: token, minPacketSize: 5);
      expect(packet.length, greaterThanOrEqualTo(5));
      expect(packet.length, greaterThanOrEqualTo(21)); // 5 padding + 16 token
    });

    test('isValidFormat returns true for generated packet', () {
      final token = List<int>.filled(16, 0xBB);
      final packet = StatelessResetGenerator.generate(token: token);
      expect(StatelessResetGenerator.isValidFormat(packet), isTrue);
    });

    test('isValidFormat returns false for short packet', () {
      expect(StatelessResetGenerator.isValidFormat(Uint8List(3)), isFalse);
    });

    test('different tokens produce different packets', () {
      final token1 = List<int>.filled(16, 0x01);
      final token2 = List<int>.filled(16, 0x02);
      final p1 = StatelessResetGenerator.generate(token: token1);
      final p2 = StatelessResetGenerator.generate(token: token2);
      expect(p1, isNot(equals(p2)));
    });

    test('invalid token length throws', () {
      expect(
        () => StatelessResetGenerator.generate(token: [1, 2, 3]),
        throwsArgumentError,
      );
    });
  });
}

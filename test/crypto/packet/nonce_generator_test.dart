import 'dart:typed_data';

import 'package:dart_quic/src/crypto/packet/nonce_generator.dart';
import 'package:test/test.dart';

void main() {
  group('NonceGenerator', () {
    test('generate produces correct nonce for known IV + PN', () {
      final iv = Uint8List.fromList([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      ]);
      const packetNumber = 2;

      final nonce = NonceGenerator.generate(iv, packetNumber);

      // iv XOR 0x00...02 => 0x00...03
      expect(nonce, equals(Uint8List.fromList([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
      ])));
    });

    test('different packet numbers produce different nonces', () {
      final iv = Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
      ]);

      final nonce1 = NonceGenerator.generate(iv, 0);
      final nonce2 = NonceGenerator.generate(iv, 1);
      final nonce3 = NonceGenerator.generate(iv, 0x010203);

      expect(nonce1, isNot(equals(nonce2)));
      expect(nonce2, isNot(equals(nonce3)));
      expect(nonce1, isNot(equals(nonce3)));
    });

    test('nonce is exactly 12 bytes', () {
      final iv = Uint8List(12);
      final nonce = NonceGenerator.generate(iv, 42);
      expect(nonce.length, equals(12));
    });

    test('throws for non-12-byte IV', () {
      expect(
        () => NonceGenerator.generate([1, 2, 3], 0),
        throwsArgumentError,
      );
      expect(
        () => NonceGenerator.generate(Uint8List(11), 0),
        throwsArgumentError,
      );
      expect(
        () => NonceGenerator.generate(Uint8List(13), 0),
        throwsArgumentError,
      );
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/retry_token_generator.dart';
import 'package:test/test.dart';

void main() {
  final backend = DefaultCryptoBackend();

  group('RetryTokenGenerator', () {
    test('generate produces non-empty token', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final token = await gen.generate(
        [192, 168, 1, 1],
        [0xAB, 0xCD],
        DateTime.now().millisecondsSinceEpoch,
      );

      expect(token, isNotEmpty);
      // 8 bytes timestamp + address + dcid + 32 bytes HMAC
      expect(token.length, greaterThanOrEqualTo(8 + 4 + 2 + 32));
    });

    test('validate returns true for valid token', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final now = DateTime.now().millisecondsSinceEpoch;
      final clientAddr = [192, 168, 1, 1];
      final dcid = [0xAB, 0xCD, 0xEF, 0x01];

      final token = await gen.generate(clientAddr, dcid, now);
      final valid = await gen.validate(token, clientAddr, dcid);

      expect(valid, isTrue);
    });

    test('validate returns false for expired token', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final oldTime = DateTime.now().millisecondsSinceEpoch - 10000;
      final clientAddr = [192, 168, 1, 1];
      final dcid = [0xAB, 0xCD, 0xEF, 0x01];

      final token = await gen.generate(clientAddr, dcid, oldTime);
      final valid = await gen.validate(
        token,
        clientAddr,
        dcid,
        maxAgeMs: 5000,
      );

      expect(valid, isFalse);
    });

    test('validate returns false for tampered token', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final now = DateTime.now().millisecondsSinceEpoch;
      final clientAddr = [192, 168, 1, 1];
      final dcid = [0xAB, 0xCD, 0xEF, 0x01];

      final token = await gen.generate(clientAddr, dcid, now);
      // Tamper with a byte in the DCID portion of the payload.
      token[10] ^= 0xFF;

      final valid = await gen.validate(token, clientAddr, dcid);

      expect(valid, isFalse);
    });

    test('validate returns false for wrong address', () async {
      final gen = await RetryTokenGenerator.create(backend);
      final now = DateTime.now().millisecondsSinceEpoch;
      final clientAddr = [192, 168, 1, 1];
      final dcid = [0xAB, 0xCD, 0xEF, 0x01];

      final token = await gen.generate(clientAddr, dcid, now);
      final wrongAddr = [10, 0, 0, 1];

      final valid = await gen.validate(token, wrongAddr, dcid);

      expect(valid, isFalse);
    });
  });
}

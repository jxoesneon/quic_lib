import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/key_derivation.dart';
import 'package:test/test.dart';

void main() {
  group('KeyDerivation', () {
    late CryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('deriveKeys produces key/iv/hpKey of correct lengths', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final result = await KeyDerivation.deriveKeys(
        secret: secret,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result.key.length, equals(16));
      expect(result.iv.length, equals(12));
      expect(result.hpKey.length, equals(16));
    });

    test('same secret produces same keys (deterministic)', () async {
      final secret = SimpleSecretKey(Uint8List(32));
      final result1 = await KeyDerivation.deriveKeys(
        secret: secret,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );
      final result2 = await KeyDerivation.deriveKeys(
        secret: secret,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result1.key, equals(result2.key));
      expect(result1.iv, equals(result2.iv));
      expect(result1.hpKey, equals(result2.hpKey));
    });

    test('different secrets produce different keys', () async {
      final secret1 = SimpleSecretKey(Uint8List.fromList(
        List.generate(32, (i) => i),
      ));
      final secret2 = SimpleSecretKey(Uint8List.fromList(
        List.generate(32, (i) => 31 - i),
      ));

      final result1 = await KeyDerivation.deriveKeys(
        secret: secret1,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );
      final result2 = await KeyDerivation.deriveKeys(
        secret: secret2,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result1.key, isNot(equals(result2.key)));
      expect(result1.iv, isNot(equals(result2.iv)));
      expect(result1.hpKey, isNot(equals(result2.hpKey)));
    });
  });
}

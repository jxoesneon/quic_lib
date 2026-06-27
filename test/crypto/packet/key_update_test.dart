import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/crypto/packet/key_update.dart';
import 'package:test/test.dart';

void main() {
  final backend = DefaultCryptoBackend();

  group('KeyUpdate', () {
    test('deriveNextSecret produces a different secret', () async {
      final currentSecret = SimpleSecretKey(List<int>.generate(32, (i) => i));
      final nextSecret = await KeyUpdate.deriveNextSecret(
        currentSecret: currentSecret,
        backend: backend,
      );

      expect(
        nextSecret.extractSync(),
        isNot(equals(currentSecret.extractSync())),
      );
    });

    test('same input produces same output (deterministic)', () async {
      final currentSecret = SimpleSecretKey(List<int>.generate(32, (i) => i));
      final nextSecret1 = await KeyUpdate.deriveNextSecret(
        currentSecret: currentSecret,
        backend: backend,
      );
      final nextSecret2 = await KeyUpdate.deriveNextSecret(
        currentSecret: currentSecret,
        backend: backend,
      );

      expect(
        nextSecret1.extractSync(),
        equals(nextSecret2.extractSync()),
      );
    });
  });
}

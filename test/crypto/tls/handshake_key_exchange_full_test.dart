import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/crypto/initial_secrets.dart';
import 'package:dart_quic/src/crypto/tls/handshake_key_exchange.dart';
import 'package:test/test.dart';

void main() {
  group('HandshakeKeyExchange full coverage', () {
    final backend = DefaultCryptoBackend();

    test('computeSharedSecret throws before key generation', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final dummyKey = _SimplePublicKey([0x01]);
      expect(
        () => exchange.computeSharedSecret(dummyKey),
        throwsStateError,
      );
    });

    test('deriveTrafficSecrets with transcriptHash', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final handshakeSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcriptHash = List<int>.filled(32, 0xCD);
      final secrets = await exchange.deriveTrafficSecrets(
        handshakeSecret,
        transcriptHash: transcriptHash,
      );
      expect(secrets.clientSecret.extractSync(), isNotEmpty);
      expect(secrets.serverSecret.extractSync(), isNotEmpty);
    });

    test('deriveMasterSecret returns a SecretKey', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final handshakeSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final masterSecret = await exchange.deriveMasterSecret(handshakeSecret);
      expect(masterSecret, isA<SecretKey>());
      expect(masterSecret.extractSync(), isNotEmpty);
    });

    test('deriveApplicationSecrets returns distinct client/server secrets', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final masterSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcriptHash = List<int>.filled(32, 0xCD);
      final appSecrets = await exchange.deriveApplicationSecrets(
        masterSecret,
        transcriptHash: transcriptHash,
      );
      expect(appSecrets.clientSecret.extractSync(), isNotEmpty);
      expect(appSecrets.serverSecret.extractSync(), isNotEmpty);
      expect(
        appSecrets.clientSecret.extractSync(),
        isNot(equals(appSecrets.serverSecret.extractSync())),
      );
    });

    test('deriveFinishedKey returns a SecretKey', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final baseKey = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final finishedKey = await exchange.deriveFinishedKey(baseKey);
      expect(finishedKey, isA<SecretKey>());
      expect(finishedKey.extractSync(), isNotEmpty);
    });

    test('computeFinishedVerifyData returns non-empty bytes', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final finishedKey = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final transcriptHash = List<int>.filled(32, 0xCD);
      final verifyData = await exchange.computeFinishedVerifyData(
        finishedKey,
        transcriptHash,
      );
      expect(verifyData, isNotEmpty);
    });

    test('deriveNextGenerationSecret returns a SecretKey', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      final currentSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final nextSecret = await exchange.deriveNextGenerationSecret(currentSecret);
      expect(nextSecret, isA<SecretKey>());
      expect(nextSecret.extractSync(), isNotEmpty);
    });

    test('role getter is stored correctly', () {
      final client = HandshakeKeyExchange(backend, HandshakeRole.client);
      final server = HandshakeKeyExchange(backend, HandshakeRole.server);
      expect(client.role, equals(HandshakeRole.client));
      expect(server.role, equals(HandshakeRole.server));
    });
  });
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

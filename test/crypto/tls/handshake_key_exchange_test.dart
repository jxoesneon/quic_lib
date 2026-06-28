import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';

void main() {
  group('HandshakeKeyExchange', () {
    final backend = DefaultCryptoBackend();

    test('generateEphemeralKeys produces non-null keys', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      await exchange.generateEphemeralKeys();

      expect(exchange.privateKey, isNotNull);
      expect(exchange.publicKey, isNotNull);
      expect(exchange.privateKey!.extractSync(), isNotEmpty);
      expect(exchange.publicKey!.bytes, isNotEmpty);
    });

    test('two parties can compute the same shared secret (X25519 symmetry)',
        () async {
      final client = HandshakeKeyExchange(backend, HandshakeRole.client);
      final server = HandshakeKeyExchange(backend, HandshakeRole.server);

      await client.generateEphemeralKeys();
      await server.generateEphemeralKeys();

      final clientShared = await client.computeSharedSecret(server.publicKey!);
      final serverShared = await server.computeSharedSecret(client.publicKey!);

      expect(
        clientShared.extractSync(),
        equals(serverShared.extractSync()),
      );
    });

    test('deriveTrafficSecrets produces distinct client and server secrets',
        () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      await exchange.generateEphemeralKeys();

      // Use a dummy handshake secret for this test.
      final handshakeSecret = SimpleSecretKey(List<int>.filled(32, 0xAB));
      final secrets = await exchange.deriveTrafficSecrets(handshakeSecret);

      expect(secrets.clientSecret.extractSync(), isNotEmpty);
      expect(secrets.serverSecret.extractSync(), isNotEmpty);
      expect(
        secrets.clientSecret.extractSync(),
        isNot(equals(secrets.serverSecret.extractSync())),
      );
    });

    test('deriveHandshakeSecret produces a SecretKey', () async {
      final exchange = HandshakeKeyExchange(backend, HandshakeRole.client);
      await exchange.generateEphemeralKeys();

      final sharedSecret = SimpleSecretKey(List<int>.filled(32, 0xCD));
      final helloHash = List<int>.filled(32, 0xEF);

      final handshakeSecret = await exchange.deriveHandshakeSecret(
        sharedSecret,
        helloHash,
      );

      expect(handshakeSecret, isA<SecretKey>());
      expect(handshakeSecret.extractSync(), isNotEmpty);
    });
  });
}

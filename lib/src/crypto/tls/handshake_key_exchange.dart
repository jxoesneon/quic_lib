import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';

/// Role of the endpoint in the TLS handshake.
enum HandshakeRole {
  client,
  server,
}

/// Scaffold for TLS 1.3 handshake key exchange using X25519.
///
/// This class encapsulates the ephemeral key generation, shared secret
/// computation, and handshake/traffic secret derivation that occur during
/// a TLS 1.3 key exchange.
///
/// **Note:** This is a scaffold for testing and pipeline integration. A full
/// TLS 1.3 implementation requires additional steps including:
/// - Transcript hash tracking across all handshake messages
/// - Certificate verification and signature validation
/// - Finished message computation and verification
/// - Key update handling
class HandshakeKeyExchange {
  final CryptoBackend backend;
  final HandshakeRole role;

  SecretKey? _privateKey;
  PublicKey? _publicKey;

  /// Creates a new [HandshakeKeyExchange] for the given [role].
  HandshakeKeyExchange(this.backend, this.role);

  /// The ephemeral private key, available after [generateEphemeralKeys].
  SecretKey? get privateKey => _privateKey;

  /// The ephemeral public key, available after [generateEphemeralKeys].
  PublicKey? get publicKey => _publicKey;

  /// Generates a new ephemeral X25519 key pair.
  ///
  /// Stores the private and public keys internally for later use.
  Future<void> generateEphemeralKeys() async {
    final keyPair = await backend.x25519GenerateKeyPair();
    _privateKey = await keyPair.secretKey;
    _publicKey = await keyPair.publicKey;
  }

  /// Computes the shared secret with the peer's public key.
  ///
  /// Requires that [generateEphemeralKeys] has been called first.
  Future<SecretKey> computeSharedSecret(PublicKey peerPublicKey) async {
    if (_privateKey == null) {
      throw StateError('Ephemeral keys have not been generated.');
    }
    return backend.x25519SharedSecret(_privateKey!, peerPublicKey);
  }

  /// Derives the handshake secret from the shared secret and hello hash.
  ///
  /// Follows the TLS 1.3 pattern of first deriving a salt with the "derived"
  /// label, then performing HKDF-Extract with that salt and the shared secret.
  ///
  /// In real TLS 1.3 this step is more involved and depends on the full
  /// transcript hash.
  Future<SecretKey> deriveHandshakeSecret(
    SecretKey sharedSecret,
    List<int> helloHash,
  ) async {
    final hash = Sha256();
    // Create a zero-filled secret to serve as the base for the derived salt.
    final zeroSecret = SimpleSecretKey(List<int>.filled(hash.hashLength, 0));

    final derivedSaltBytes = await backend.hkdfExpandLabel(
      hash,
      zeroSecret,
      'derived',
      helloHash,
      hash.hashLength,
    );

    final derivedSalt = SimpleSecretKey(derivedSaltBytes);
    return backend.hkdfExtract(hash, derivedSalt, sharedSecret);
  }

  /// Derives client and server handshake traffic secrets.
  ///
  /// Uses HKDF-Expand-Label with the TLS 1.3 labels. In a full implementation
  /// the context would be the transcript hash of all messages up to ServerHello.
  Future<({SecretKey clientSecret, SecretKey serverSecret})>
      deriveTrafficSecrets(
    SecretKey handshakeSecret,
  ) async {
    final hash = Sha256();
    const secretLength = 32;

    final clientBytes = await backend.hkdfExpandLabel(
      hash,
      handshakeSecret,
      'client hs traffic',
      <int>[],
      secretLength,
    );

    final serverBytes = await backend.hkdfExpandLabel(
      hash,
      handshakeSecret,
      'server hs traffic',
      <int>[],
      secretLength,
    );

    return (
      clientSecret: SimpleSecretKey(clientBytes),
      serverSecret: SimpleSecretKey(serverBytes),
    );
  }
}

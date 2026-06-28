import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';

/// Role of the endpoint in the TLS handshake.
enum HandshakeRole {
  client,
  server,
}

/// TLS 1.3 handshake key exchange using X25519.
///
/// This class encapsulates the ephemeral key generation, shared secret
/// computation, and handshake/traffic secret derivation that occur during
/// a TLS 1.3 key exchange per RFC 8446.
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
  /// Uses HKDF-Expand-Label with the TLS 1.3 labels.
  /// [transcriptHash] should be the hash of all handshake messages up to
  /// and including ServerHello.
  Future<({SecretKey clientSecret, SecretKey serverSecret})>
      deriveTrafficSecrets(
    SecretKey handshakeSecret, {
    List<int>? transcriptHash,
  }) async {
    final hash = Sha256();
    const secretLength = 32;
    final context = transcriptHash ?? <int>[];

    final clientBytes = await backend.hkdfExpandLabel(
      hash,
      handshakeSecret,
      'c hs traffic',
      context,
      secretLength,
    );

    final serverBytes = await backend.hkdfExpandLabel(
      hash,
      handshakeSecret,
      's hs traffic',
      context,
      secretLength,
    );

    return (
      clientSecret: SimpleSecretKey(clientBytes),
      serverSecret: SimpleSecretKey(serverBytes),
    );
  }

  /// Derives the master secret from the handshake secret.
  ///
  /// Per RFC 8446 Section 7.1, the master secret is derived by extracting
  /// with a zero-filled IKM from the handshake secret.
  Future<SecretKey> deriveMasterSecret(SecretKey handshakeSecret) async {
    final hash = Sha256();
    final zeroIkm = SimpleSecretKey(List<int>.filled(hash.hashLength, 0));
    return backend.hkdfExtract(hash, handshakeSecret, zeroIkm);
  }

  /// Derives client and server application traffic secrets from the master secret.
  ///
  /// [transcriptHash] should be the hash of all handshake messages up to
  /// and including the server Finished message.
  Future<({SecretKey clientSecret, SecretKey serverSecret})>
      deriveApplicationSecrets(
    SecretKey masterSecret, {
    required List<int> transcriptHash,
  }) async {
    final hash = Sha256();
    const secretLength = 32;

    final clientBytes = await backend.hkdfExpandLabel(
      hash,
      masterSecret,
      'c ap traffic',
      transcriptHash,
      secretLength,
    );

    final serverBytes = await backend.hkdfExpandLabel(
      hash,
      masterSecret,
      's ap traffic',
      transcriptHash,
      secretLength,
    );

    return (
      clientSecret: SimpleSecretKey(clientBytes),
      serverSecret: SimpleSecretKey(serverBytes),
    );
  }

  /// Derives the finished key from a traffic secret.
  ///
  /// Per RFC 8446 Section 4.4.4, the finished key is:
  ///   HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
  Future<SecretKey> deriveFinishedKey(SecretKey baseKey) async {
    final hash = Sha256();
    final keyBytes = await backend.hkdfExpandLabel(
      hash,
      baseKey,
      'finished',
      <int>[],
      hash.hashLength,
    );
    return SimpleSecretKey(keyBytes);
  }

  /// Computes a TLS 1.3 Finished verify data.
  ///
  /// Per RFC 8446 Section 4.4.4:
  ///   verify_data = HMAC(finished_key, Hash(transcript))
  ///
  /// [finishedKey] is derived from the handshake traffic secret via
  /// [deriveFinishedKey]. [transcriptHash] is the hash of all handshake
  /// messages up to but not including the Finished message itself.
  Future<List<int>> computeFinishedVerifyData(
    SecretKey finishedKey,
    List<int> transcriptHash,
  ) async {
    final hash = Sha256();
    return backend.hmac(hash, finishedKey, transcriptHash);
  }

  /// Derives updated traffic secrets for a key update.
  ///
  /// Per RFC 8446 Section 4.6.3, the next-generation application traffic
  /// secret is derived from the current one:
  ///   next_secret = HKDF-Expand-Label(current_secret, "application_traffic_secret_N+1", "", Hash.length)
  Future<SecretKey> deriveNextGenerationSecret(SecretKey currentSecret) async {
    final hash = Sha256();
    final nextBytes = await backend.hkdfExpandLabel(
      hash,
      currentSecret,
      'application_traffic_secret',
      <int>[],
      hash.hashLength,
    );
    return SimpleSecretKey(nextBytes);
  }
}

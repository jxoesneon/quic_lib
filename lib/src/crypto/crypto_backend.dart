/// Opaque handle to a secret key.
abstract class SecretKey {
  /// Extracts the raw key bytes synchronously.
  List<int> extractSync();
}

/// Opaque handle to a public key.
abstract class PublicKey {
  /// Raw public key bytes.
  List<int> get bytes;
}

/// Opaque handle to a key pair.
abstract class KeyPair {
  /// The secret (private) key.
  Future<SecretKey> get secretKey;

  /// The public key.
  Future<PublicKey> get publicKey;
}

/// AEAD algorithm descriptor.
abstract class AeadAlgorithm {
  /// Human-readable name, e.g. 'AES-128-GCM'.
  String get name;

  /// Key length in bytes.
  int get keyLength;

  /// Nonce length in bytes (typically 12).
  int get nonceLength;

  /// Tag length in bytes (typically 16).
  int get tagLength;
}

/// Hash algorithm descriptor.
abstract class HashAlgorithm {
  /// Human-readable name, e.g. 'SHA-256'.
  String get name;

  /// Digest length in bytes.
  int get hashLength;
}

/// Result of an AEAD encryption operation.
abstract class AeadResult {
  /// Ciphertext including the authentication tag.
  List<int> get ciphertext;

  /// Separate authentication tag, if the backend exposes it.
  List<int> get tag;
}

/// Crypto primitive backend abstraction.
///
/// TLS 1.3 and QUIC packet protection need AES-GCM, ChaCha20-Poly1305,
/// HKDF, X25519, and Ed25519. This interface lets dart_quic swap between
/// package:cryptography, package:pointycastle, and future backends without
/// rewriting protocol logic.
abstract class CryptoBackend {
  /// Human-readable backend name (e.g. 'cryptography', 'pointycastle').
  String get name;

  /// Lists the TLS 1.3 cipher suites this backend can service.
  List<String> supportedCipherSuites();

  // -------------------------------------------------------------------------
  // Random bytes
  // -------------------------------------------------------------------------

  /// Generates [length] cryptographically secure random bytes.
  Future<List<int>> randomBytes(int length);

  // -------------------------------------------------------------------------
  // Hashes and HMAC
  // -------------------------------------------------------------------------

  /// Computes a SHA-256 digest.
  Future<List<int>> sha256(List<int> data);

  /// Computes a SHA-384 digest.
  Future<List<int>> sha384(List<int> data);

  /// Computes HMAC with the given hash algorithm.
  Future<List<int>> hmac(HashAlgorithm hash, SecretKey key, List<int> data);

  // -------------------------------------------------------------------------
  // HKDF (RFC 5869)
  // -------------------------------------------------------------------------

  /// HKDF-Extract.
  Future<SecretKey> hkdfExtract(
    HashAlgorithm hash,
    SecretKey salt,
    SecretKey ikm,
  );

  /// HKDF-Expand.
  Future<List<int>> hkdfExpand(
    HashAlgorithm hash,
    SecretKey prk,
    List<int> info,
    int length,
  );

  /// HKDF-Expand-Label with the TLS 1.3 label prefix.
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  );

  // -------------------------------------------------------------------------
  // AEAD
  // -------------------------------------------------------------------------

  /// AEAD encrypt. Returns ciphertext + tag.
  Future<AeadResult> aeadEncrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> plaintext, {
    List<int>? associatedData,
  });

  /// AEAD decrypt. Returns plaintext or throws a decryption error.
  Future<List<int>> aeadDecrypt(
    AeadAlgorithm aead,
    SecretKey key,
    List<int> nonce,
    List<int> ciphertext, {
    List<int>? associatedData,
  });

  // -------------------------------------------------------------------------
  // Key exchange (X25519)
  // -------------------------------------------------------------------------

  /// Generates a new X25519 key pair.
  Future<KeyPair> x25519GenerateKeyPair();

  /// Performs X25519 ECDH.
  Future<SecretKey> x25519SharedSecret(
      SecretKey privateKey, PublicKey publicKey);

  // -------------------------------------------------------------------------
  // Signatures (Ed25519)
  // -------------------------------------------------------------------------

  /// Generates a new Ed25519 key pair.
  Future<KeyPair> ed25519GenerateKeyPair();

  /// Signs [message] with the Ed25519 private key.
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message);

  /// Verifies an Ed25519 signature.
  Future<bool> ed25519Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  );

  // -------------------------------------------------------------------------
  // ECDSA (P-256) for TLS certificate verification
  // -------------------------------------------------------------------------

  /// Generates a new ECDSA P-256 key pair.
  Future<KeyPair> ecdsaP256GenerateKeyPair();

  /// Verifies an ECDSA P-256 signature using SHA-256.
  Future<bool> ecdsaP256Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  );

  // -------------------------------------------------------------------------
  // RSA signatures (for legacy certificate chains)
  // -------------------------------------------------------------------------

  /// Verifies an RSASSA-PKCS1-v1_5 signature using the given hash.
  Future<bool> rsaPkcs1Verify(
    PublicKey publicKey,
    HashAlgorithm hash,
    List<int> message,
    List<int> signature,
  );
}

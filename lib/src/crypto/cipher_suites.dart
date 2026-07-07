import 'crypto_backend.dart';

/// AES-128-GCM AEAD algorithm constants.
class Aes128Gcm implements AeadAlgorithm {
  /// Creates an AES-128-GCM algorithm descriptor.
  const Aes128Gcm();

  @override
  String get name => 'AES-128-GCM';

  @override
  int get keyLength => 16;

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;
}

/// AES-256-GCM AEAD algorithm constants.
class Aes256Gcm implements AeadAlgorithm {
  /// Creates an AES-256-GCM algorithm descriptor.
  const Aes256Gcm();

  @override
  String get name => 'AES-256-GCM';

  @override
  int get keyLength => 32;

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;
}

/// ChaCha20-Poly1305 AEAD algorithm constants.
class ChaCha20Poly1305 implements AeadAlgorithm {
  /// Creates a ChaCha20-Poly1305 algorithm descriptor.
  const ChaCha20Poly1305();

  @override
  String get name => 'ChaCha20-Poly1305';

  @override
  int get keyLength => 32;

  @override
  int get nonceLength => 12;

  @override
  int get tagLength => 16;
}

/// SHA-256 hash algorithm constants.
class Sha256 implements HashAlgorithm {
  /// Creates a SHA-256 hash algorithm descriptor.
  const Sha256();

  @override
  String get name => 'SHA-256';

  @override
  int get hashLength => 32;
}

/// SHA-384 hash algorithm constants.
class Sha384 implements HashAlgorithm {
  /// Creates a SHA-384 hash algorithm descriptor.
  const Sha384();

  @override
  String get name => 'SHA-384';

  @override
  int get hashLength => 48;
}

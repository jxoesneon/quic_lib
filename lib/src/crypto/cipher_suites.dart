import 'crypto_backend.dart';

/// AES-128-GCM AEAD algorithm constants.
class Aes128Gcm implements AeadAlgorithm {
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
  @override
  String get name => 'SHA-256';

  @override
  int get hashLength => 32;
}

/// SHA-384 hash algorithm constants.
class Sha384 implements HashAlgorithm {
  @override
  String get name => 'SHA-384';

  @override
  int get hashLength => 48;
}

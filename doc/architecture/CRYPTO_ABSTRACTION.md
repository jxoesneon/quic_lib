---
title: "Crypto Backend Abstraction"
category: architecture
version: "1.0-draft"
status: "Draft"
subsystem: "Crypto Backend"
---

# Crypto Backend Abstraction


## 1. Purpose

TLS 1.3 and QUIC packet protection need AES-GCM, ChaCha20-Poly1305, HKDF, X25519, and Ed25519-but no single Dart package covers all platforms optimally. Without a backend abstraction, the project would be locked into one dependency that might become unmaintained or unsupported on WASM. This architecture defines the CryptoBackend interface that lets dart_quic swap between package:cryptography, package:pointycastle, and future backends without rewriting protocol logic.

## 2. Detailed Specification
### 2.1 Design Principles

1. **No TLS semantics in the backend.** The backend is a primitive provider; the TLS engine owns the handshake state machine and key schedule.
2. **Opaque key handles.** Secret and private key material is returned as opaque byte containers so that implementations can keep keys in platform keystores if they choose.
3. **Cipher-suite oriented.** TLS 1.3 cipher suites are the primary unit of configuration; the backend reports which suites it supports.
4. **Async-by-default, sync where needed.** AEAD, KDF, and key exchange are exposed as `Future` to allow isolate or platform offloading, with synchronous variants available for deterministic tests.
5. **Zero `dart:ffi` in the core.** The default backends are pure Dart or use Flutter platform channels. A native FFI backend may be added later behind the same interface.

---


### 2.2 Supported Cipher Suites

The backend must support at least the TLS 1.3 cipher suites required by QUIC:

| Cipher Suite | AEAD | Hash | Key Length | Notes |
|-------------|------|------|------------|-------|
| `TLS_AES_128_GCM_SHA256` | AES-128-GCM | SHA-256 | 16 bytes | Required by QUIC. |
| `TLS_AES_256_GCM_SHA384` | AES-256-GCM | SHA-384 | 32 bytes | Optional but widely supported. |
| `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | SHA-256 | 32 bytes | Required for mobile/web without AES-NI. |

The backend advertises support via `supportedCipherSuites()` so that the TLS engine can negotiate appropriately.

---


### 2.3 Backend Interface

> **Note:** The public crypto backend API consumed by applications is defined in [DART_API_SPEC.md §2.9](../specs/DART_API_SPEC.md#29-crypto-backend-abstraction). The following interface documents the internal architecture contract between the crypto backend and the rest of the `dart_quic` stack. It is documented as pseudocode; concrete implementations may add factory constructors, helper methods, or platform-specific optimizations.

```dart
/// Opaque handle to a secret key.
abstract class SecretKey {
  List<int> extractSync();
}

/// Opaque handle to a public key.
abstract class PublicKey {
  List<int> get bytes;
}

/// Opaque handle to a key pair.
abstract class KeyPair {
  Future<SecretKey> get secretKey;
  Future<PublicKey> get publicKey;
}

/// AEAD algorithm descriptor.
abstract class AeadAlgorithm {
  String get name;                 // e.g., 'AES-128-GCM'
  int get keyLength;
  int get nonceLength;             // typically 12 bytes
  int get tagLength;               // typically 16 bytes
}

/// Hash algorithm descriptor.
abstract class HashAlgorithm {
  String get name;                 // e.g., 'SHA-256'
  int get hashLength;
}

/// Result of an AEAD operation.
abstract class AeadResult {
  List<int> get ciphertext;        // includes the authentication tag
  List<int> get tag;               // separate tag if the backend exposes it
}

/// Crypto primitive backend.
abstract class CryptoBackend {
  /// Human-readable backend name (e.g., 'cryptography', 'pointycastle').
  String get name;

  /// Lists the TLS 1.3 cipher suites this backend can service.
  List<String> supportedCipherSuites();

  // --------------------------------------------------------------------
  // Random bytes
  // --------------------------------------------------------------------

  /// Generates `length` cryptographically secure random bytes.
  Future<List<int>> randomBytes(int length);

  // --------------------------------------------------------------------
  // Hashes and HMAC
  // --------------------------------------------------------------------

  /// Computes a SHA-256 digest.
  Future<List<int>> sha256(List<int> data);

  /// Computes a SHA-384 digest.
  Future<List<int>> sha384(List<int> data);

  /// Computes HMAC with the given hash algorithm.
  Future<List<int>> hmac(HashAlgorithm hash, SecretKey key, List<int> data);

  // --------------------------------------------------------------------
  // HKDF (RFC 5869)
  // --------------------------------------------------------------------

  /// HKDF-Extract.
  Future<SecretKey> hkdfExtract(HashAlgorithm hash, SecretKey salt, SecretKey ikm);

  /// HKDF-Expand.
  Future<List<int>> hkdfExpand(HashAlgorithm hash, SecretKey prk, List<int> info, int length);

  /// HKDF-Expand-Label with the TLS 1.3 label prefix.
  Future<List<int>> hkdfExpandLabel(
    HashAlgorithm hash,
    SecretKey secret,
    String label,
    List<int> context,
    int length,
  );

  // --------------------------------------------------------------------
  // AEAD
  // --------------------------------------------------------------------

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

  // --------------------------------------------------------------------
  // Key exchange (X25519)
  // --------------------------------------------------------------------

  /// Generates a new X25519 key pair.
  Future<KeyPair> x25519GenerateKeyPair();

  /// Performs X25519 ECDH.
  Future<SecretKey> x25519SharedSecret(SecretKey privateKey, PublicKey publicKey);

  // --------------------------------------------------------------------
  // Signatures (Ed25519)
  // --------------------------------------------------------------------

  /// Generates a new Ed25519 key pair.
  Future<KeyPair> ed25519GenerateKeyPair();

  /// Signs `message` with the Ed25519 private key.
  Future<List<int>> ed25519Sign(SecretKey privateKey, List<int> message);

  /// Verifies an Ed25519 signature.
  Future<bool> ed25519Verify(PublicKey publicKey, List<int> message, List<int> signature);

  // --------------------------------------------------------------------
  // ECDSA (P-256) for TLS certificate verification
  // --------------------------------------------------------------------

  /// Generates a new ECDSA P-256 key pair.
  Future<KeyPair> ecdsaP256GenerateKeyPair();

  /// Verifies an ECDSA P-256 signature using SHA-256.
  Future<bool> ecdsaP256Verify(
    PublicKey publicKey,
    List<int> message,
    List<int> signature,
  );

  // --------------------------------------------------------------------
  // RSA signatures (for legacy certificate chains)
  // --------------------------------------------------------------------

  /// Verifies an RSASSA-PKCS1-v1_5 signature using the given hash.
  Future<bool> rsaPkcs1Verify(
    PublicKey publicKey,
    HashAlgorithm hash,
    List<int> message,
    List<int> signature,
  );
}
```

---


### 2.4 Backend Implementations


#### 2.4.1 `CryptographyBackend` (default)

- **Package**: `package:cryptography` (and optionally `package:cryptography_flutter` for native acceleration).
- **Role**: Default backend on all targets.
- **Strengths**: Hardware-accelerated AES-GCM and ChaCha20-Poly1305 on Android/iOS/macOS, Web Crypto on browsers, pure Dart fallbacks elsewhere.
- **Implementation notes**:
  - Map `AeadAlgorithm` to `package:cryptography` `Cipher` instances (`AesGcm`, `Chacha20.poly1305Aead`).
  - Map `HashAlgorithm` to `Sha256` / `Sha384`.
  - Use `Hkdf` for HKDF operations.
  - Use `X25519` and `Ed25519` classes for key exchange and signatures.
  - RSA/ECDSA verification can use `package:cryptography` higher-level classes where available, with `package:pointycastle` as a fallback for unsupported curves.


#### 2.4.2 `PointyCastleBackend` (fallback)

- **Package**: `package:pointycastle`.
- **Role**: Pure-Dart fallback for constrained environments or when `package:cryptography` cannot reach a platform API.
- **Strengths**: No platform dependencies; broad algorithm catalogue; works in `dart2wasm` and other restricted targets.
- **Implementation notes**:
  - Use the registry to instantiate `AEADCipher('AES/GCM')`, `AEADCipher('ChaCha20-Poly1305')`, `Digest('SHA-256')`, `HMac('SHA-256')`, etc.
  - Implement HKDF with `HkdfParameters`.
  - Use `package:pointycastle` EC and RSA classes for certificate verification.


#### 2.4.3 Future backends

The same interface can host:
- A **Web Crypto backend** (browser-only, no `package:cryptography` wrapper).
- A **native FFI backend** (e.g., OpenSSL/BoringSSL via `dart:ffi`) for high-throughput server deployments, gated behind a non-default import.
- A **deterministic test backend** that uses fixed randomness and known keys for reproducible RFC test vectors.

---


### 2.5 Backend Selection and Configuration

```dart
abstract class CryptoBackendFactory {
  /// Creates the preferred backend for the current platform.
  static CryptoBackend createDefault();

  /// Creates the pure-Dart fallback backend.
  static CryptoBackend createFallback();

  /// Creates a test backend with deterministic randomness.
  static CryptoBackend createTest({List<int>? seed});
}
```

- `QuicConfiguration` gains an optional `CryptoBackend? cryptoBackend` parameter. When omitted, the factory selects the default backend.
- The TLS engine and packet-protection layer receive the backend via constructor injection, never by global singleton.
- This allows unit tests to inject a deterministic backend and interop tests to run both backends against the same test vectors.

---


### 2.6 Usage Flow

```
QuicConfiguration
  │
  ├── CryptoBackend (selected by factory or user)
  │      ├── TLS 1.3 Engine (key exchange, signatures, key schedule)
  │      │      └── CRYPTO frames → QuicConnection
  │      │
  │      └── Packet Protector (AEAD encrypt/decrypt, header protection)
  │             └── QuicEndpoint / QuicConnection
```

All crypto operations required by the TLS engine and the QUIC packet protector go through the `CryptoBackend` interface. X.509 parsing and validation sits adjacent to the backend: the TLS engine uses `CryptoBackend` for signature verification and `package:x509` (or a future parser) for certificate decoding.

---






## 3. Acceptance Criteria

- [ ] A `CryptoBackend` implementation can be swapped without changing TLS or QUIC packet-protection code.
- [ ] Both `CryptographyBackend` and `PointyCastleBackend` pass the same RFC 9001 / RFC 8446 test vectors.
- [ ] The default backend produces correct AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 output.
- [ ] HKDF-Expand-Label matches the TLS 1.3 specification for all supported hash algorithms.
- [ ] Ed25519 and X25519 operations are available in both backends.
- [ ] A deterministic test backend can reproduce fixed test vectors for handshake and packet-protection tests.

---







## 4. Used By

- [API_SURFACE.md](API_SURFACE.md) — Referenced alongside authoritative API spec.



## 5. References

- `TLS_LIBRARY_DECISION.md` — rationale for choosing the default and fallback backends.
- `QUIC_CRYPTO_SPEC.md` — QUIC packet protection and key schedule details.
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869
- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446
- RFC 9001 (QUIC TLS): https://www.rfc-editor.org/rfc/rfc9001
- `package:cryptography`: https://pub.dev/packages/cryptography
- `package:pointycastle`: https://pub.dev/packages/pointycastle
- `package:x509`: https://pub.dev/packages/x509
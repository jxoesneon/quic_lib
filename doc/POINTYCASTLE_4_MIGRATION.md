# pointycastle 4.0.0 Migration Assessment

**Date:** 2026-06-27  
**Current:** pointycastle ^3.7.0 (resolved to 3.9.1)  
**Target:** pointycastle ^4.0.0

---

## 4.0.0 Changelog Summary (2025-02-12)

### Additions (no breaking changes)
- UTF-16 support in `ans1_bmp_string.dart`
- New OID for secp256r1 (PR #249)
- New OIDs for elliptic curves (PR #240, #242)
- Blowfish, Camellia, Twofish block cipher engines (PR #246)
- SHA512 factory in RSA-OAEP (PR #227)
- Generics added to `generateKeyPair` (PR #191)

### Fixes (no breaking changes)
- Null-safety error in `padded_block_cipher_impl.dart` (PR #254)
- ASN1Parser length parsing (PR #250)

### Removals
- Removed unused `js` dependency (PR #251) — **positive for us** since `package:js` is discontinued

## Breaking Change Analysis

| Change | Impact on dart_quic | Action Required |
|--------|---------------------|-----------------|
| `generateKeyPair` generics | `DefaultCryptoBackend` uses `generateKeyPair` via `package:cryptography`, not pointycastle directly | **None** — indirect usage |
| New block ciphers | We do not use Blowfish, Camellia, or Twofish | **None** |
| RSA-OAEP SHA512 factory | We use `Sha256` for RSA-OAEP | **None** |
| ASN1Parser length fix | Could affect `_parseRsaPublicKey` in `default_crypto_backend.dart` | **Test** after upgrade |
| `js` removal | Positive — removes discontinued dependency | **None** |

## Migration Risk: LOW

No API breaking changes affect dart_quic's direct usage. The only touchpoint is ASN1 parsing for RSA public keys, which is improved (bug fix, not breakage).

## Recommended Action

1. Update `pubspec.yaml`: `pointycastle: ^4.0.0`
2. Run `dart pub upgrade`
3. Run full test suite (especially `test/crypto/`)
4. Verify `rsaPkcs1Verify` still works with real and malformed keys

## Blocker: None

Migration can proceed at any time. No code changes required in dart_quic.

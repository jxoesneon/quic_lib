import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';

/// Generates and validates QUIC Retry tokens per RFC 9000.
///
/// Token format:
///   timestamp (8 bytes, big-endian uint64)
///   || clientAddress
///   || dcid
///   || HMAC-SHA256(timestamp || clientAddress || dcid)
///
/// SECURITY: A random 32-byte secret key is generated on construction.
class RetryTokenGenerator {
  final CryptoBackend _backend;
  final SecretKey _secretKey;

  RetryTokenGenerator._(this._backend, this._secretKey);

  /// Creates a new generator with a randomly generated secret key.
  static Future<RetryTokenGenerator> create(CryptoBackend backend) async {
    final keyBytes = await backend.randomBytes(32);
    return RetryTokenGenerator._(backend, SimpleSecretKey(keyBytes));
  }

  /// Generate a Retry token for the given client address and DCID.
  ///
  /// [timestamp] should be milliseconds since epoch (e.g.
  /// [DateTime.now().millisecondsSinceEpoch]).
  Future<Uint8List> generate(
    List<int> clientAddress,
    List<int> dcid,
    int timestamp,
  ) async {
    final timestampBytes = _encodeUint64(timestamp);

    final payload = Uint8List(8 + clientAddress.length + dcid.length);
    payload.setAll(0, timestampBytes);
    payload.setAll(8, clientAddress);
    payload.setAll(8 + clientAddress.length, dcid);

    final hmacBytes = await _backend.hmac(Sha256(), _secretKey, payload);

    final token = Uint8List(payload.length + hmacBytes.length);
    token.setAll(0, payload);
    token.setAll(payload.length, hmacBytes);
    return token;
  }

  /// Validate a Retry token for the given client address and DCID.
  ///
  /// Returns `true` only if:
  /// - the token is long enough to contain all fields plus a 32-byte HMAC,
  /// - the embedded timestamp has not expired (default max age 5000 ms),
  /// - the embedded client address and DCID match the provided values, and
  /// - the HMAC-SHA256 over the payload verifies.
  Future<bool> validate(
    Uint8List token,
    List<int> clientAddress,
    List<int> dcid, {
    int maxAgeMs = 5000,
  }) async {
    final expectedPayloadLen = 8 + clientAddress.length + dcid.length;
    final minLen = expectedPayloadLen + 32; // SHA-256 HMAC length
    if (token.length < minLen) {
      return false;
    }

    final timestamp = _decodeUint64(token.sublist(0, 8));
    final now = DateTime.now().millisecondsSinceEpoch;
    if (now - timestamp > maxAgeMs) {
      return false;
    }

    // Verify the client address embedded in the token matches.
    final tokenAddr = token.sublist(8, 8 + clientAddress.length);
    if (!_listsEqual(tokenAddr, clientAddress)) {
      return false;
    }

    // Verify the DCID embedded in the token matches.
    final tokenDcid = token.sublist(
      8 + clientAddress.length,
      expectedPayloadLen,
    );
    if (!_listsEqual(tokenDcid, dcid)) {
      return false;
    }

    final payload = token.sublist(0, expectedPayloadLen);
    final actualHmac = token.sublist(expectedPayloadLen);
    final expectedHmac = await _backend.hmac(Sha256(), _secretKey, payload);

    return _listsEqual(expectedHmac, actualHmac);
  }

  static Uint8List _encodeUint64(int value) {
    final result = Uint8List(8);
    var v = value;
    for (var i = 7; i >= 0; i--) {
      result[i] = v & 0xFF;
      v >>= 8;
    }
    return result;
  }

  static int _decodeUint64(List<int> bytes) {
    var result = 0;
    for (var i = 0; i < bytes.length && i < 8; i++) {
      result = (result << 8) | bytes[i];
    }
    return result;
  }

  static bool _listsEqual(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }
}

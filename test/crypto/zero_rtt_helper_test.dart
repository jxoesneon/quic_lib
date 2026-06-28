import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/zero_rtt_helper.dart';
import 'package:test/test.dart';

void main() {
  group('ZeroRttHelper', () {
    late CryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('deriveKeys produces key/iv/hpKey of correct lengths', () async {
      final psk = SimpleSecretKey(Uint8List(32));
      final result = await ZeroRttHelper.deriveKeys(
        psk: psk,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result.key.length, equals(16));
      expect(result.iv.length, equals(12));
      expect(result.hpKey.length, equals(16));
    });

    test('isAcceptable true for positive maxEarlyData', () {
      expect(ZeroRttHelper.isAcceptable(1), isTrue);
      expect(ZeroRttHelper.isAcceptable(0xFFFFFFFF), isTrue);
    });

    test('isAcceptable false for zero', () {
      expect(ZeroRttHelper.isAcceptable(0), isFalse);
    });

    test('same PSK produces same keys (deterministic)', () async {
      final psk = SimpleSecretKey(Uint8List(32));
      final result1 = await ZeroRttHelper.deriveKeys(
        psk: psk,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );
      final result2 = await ZeroRttHelper.deriveKeys(
        psk: psk,
        keyLength: 16,
        hpKeyLength: 16,
        backend: backend,
      );

      expect(result1.key, equals(result2.key));
      expect(result1.iv, equals(result2.iv));
      expect(result1.hpKey, equals(result2.hpKey));
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/packet/retry_integrity_tag.dart';
import 'package:test/test.dart';

void main() {
  final backend = DefaultCryptoBackend();

  group('RetryIntegrityTag', () {
    test('compute produces a 16-byte tag', () async {
      final originalDcid = [0xab, 0xcd, 0xef, 0x01];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xf0, 0x00, 0x00, 0x00]);

      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
      );

      expect(tag.length, equals(16));
    });

    test('verify succeeds for correctly computed tag', () async {
      final originalDcid = [0xab, 0xcd, 0xef, 0x01];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xf0, 0x00, 0x00, 0x00]);

      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
      );

      final retryPacket = Uint8List.fromList([
        ...retryPacketWithoutTag,
        ...tag,
      ]);

      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: retryPacket,
        backend: backend,
      );

      expect(valid, isTrue);
    });

    test('verify fails for tampered packet', () async {
      final originalDcid = [0xab, 0xcd, 0xef, 0x01];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xf0, 0x00, 0x00, 0x00]);

      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
      );

      final retryPacket = Uint8List.fromList([
        ...retryPacketWithoutTag,
        ...tag,
      ]);
      // Tamper with a byte in the retry packet body.
      retryPacket[2] ^= 0xFF;

      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: retryPacket,
        backend: backend,
      );

      expect(valid, isFalse);
    });
  });
}

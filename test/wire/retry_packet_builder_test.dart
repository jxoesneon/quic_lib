import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/packet/retry_integrity_tag.dart';
import 'package:quic_lib/src/wire/retry_packet_builder.dart';
import 'package:test/test.dart';

void main() {
  final backend = DefaultCryptoBackend();

  group('RetryPacketBuilder', () {
    test('build produces non-empty packet', () async {
      final packet = await RetryPacketBuilder.build(
        version: 0x00000001,
        originalDestinationConnectionId: [0xab, 0xcd, 0xef, 0x01],
        retrySourceConnectionId: [0x12, 0x34],
        retryToken: [0xde, 0xad, 0xbe, 0xef],
        backend: backend,
      );

      expect(packet, isNotEmpty);
    });

    test('packet starts with 0xF0', () async {
      final packet = await RetryPacketBuilder.build(
        version: 0x00000001,
        originalDestinationConnectionId: [0xab, 0xcd, 0xef, 0x01],
        retrySourceConnectionId: [0x12, 0x34],
        retryToken: [0xde, 0xad, 0xbe, 0xef],
        backend: backend,
      );

      expect(packet[0], equals(0xF0));
    });

    test('verify succeeds for built packet', () async {
      final originalDcid = [0xab, 0xcd, 0xef, 0x01];
      final packet = await RetryPacketBuilder.build(
        version: 0x00000001,
        originalDestinationConnectionId: originalDcid,
        retrySourceConnectionId: [0x12, 0x34],
        retryToken: [0xde, 0xad, 0xbe, 0xef],
        backend: backend,
      );

      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: packet,
        backend: backend,
      );

      expect(valid, isTrue);
    });

    test('different tokens produce different packets', () async {
      final packetA = await RetryPacketBuilder.build(
        version: 0x00000001,
        originalDestinationConnectionId: [0xab, 0xcd, 0xef, 0x01],
        retrySourceConnectionId: [0x12, 0x34],
        retryToken: [0x00, 0x00, 0x00, 0x00],
        backend: backend,
      );

      final packetB = await RetryPacketBuilder.build(
        version: 0x00000001,
        originalDestinationConnectionId: [0xab, 0xcd, 0xef, 0x01],
        retrySourceConnectionId: [0x12, 0x34],
        retryToken: [0xFF, 0xFF, 0xFF, 0xFF],
        backend: backend,
      );

      expect(packetA, isNot(equals(packetB)));
    });
  });
}

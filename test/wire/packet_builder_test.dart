import 'package:test/test.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';

void main() {
  group('PacketBuilder.build', () {
    test('Initial with CRYPTO frame', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 0,
        token: const [],
      );
      final frames = [
        CryptoFrame(offset: 0, data: [0x01, 0x02])
      ];
      final packet = await PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header
    });

    test('ShortHeader with STREAM frame', () async {
      final header = ShortHeader(
        destinationConnectionId: [0xAB, 0xCD],
        packetNumber: 42,
        packetNumberLength: 1,
      );
      final frames = [
        StreamFrame(streamId: 0, data: [0xAA, 0xBB, 0xCC])
      ];
      final packet = await PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, equals(0)); // short header
    });

    test('Retry has no frames', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
        backend: DefaultCryptoBackend(),
      );
      final packet = await PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header
    });

    test('empty frames produces valid packet', () async {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
      );
      final packet = await PacketBuilder.build(header, []);
      expect(packet.length, equals(1 + 1 + 1)); // header byte + DCID + PN
    });

    test('Initial packet is padded to at least 1200 bytes', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 0,
        token: const [],
      );
      final frames = [
        CryptoFrame(offset: 0, data: [0x01, 0x02])
      ];
      final packet = await PacketBuilder.build(header, frames);
      expect(packet.length, greaterThanOrEqualTo(1200));
      // The packet should still be a long header Initial packet.
      expect(packet[0] & 0x80, isNonZero);
      expect((packet[0] >> 4) & 0x03, equals(0x00)); // Initial type
    });
  });
}

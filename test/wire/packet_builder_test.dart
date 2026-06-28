import 'package:test/test.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('PacketBuilder.build', () {
    test('Initial with CRYPTO frame', () {
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
      final packet = PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header
    });

    test('ShortHeader with STREAM frame', () {
      final header = ShortHeader(
        destinationConnectionId: [0xAB, 0xCD],
        packetNumber: 42,
        packetNumberLength: 1,
      );
      final frames = [
        StreamFrame(streamId: 0, data: [0xAA, 0xBB, 0xCC])
      ];
      final packet = PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, equals(0)); // short header
    });

    test('Retry has no frames', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header
    });

    test('empty frames produces valid packet', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.length, equals(1 + 1 + 1)); // header byte + DCID + PN
    });
  });
}

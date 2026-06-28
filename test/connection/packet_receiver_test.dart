import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';

void main() {
  group('PacketReceiver.spaceFromHeader', () {
    test('Initial → initial space', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header),
          equals(PacketNumberSpace.initial));
    });

    test('Handshake → handshake space', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header),
          equals(PacketNumberSpace.handshake));
    });

    test('ShortHeader → application space', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header),
          equals(PacketNumberSpace.application));
    });

    test('Retry → null', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xFF],
      );
      expect(PacketReceiver.spaceFromHeader(header), isNull);
    });

    test('ZeroRtt → application space', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header),
          equals(PacketNumberSpace.application));
    });

    test('unknown long header type → null', () {
      // Use VersionNegotiationPacket as an unknown header type
      final header = VersionNegotiationPacket(
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        supportedVersions: [0x00000001],
      );
      expect(PacketReceiver.spaceFromHeader(header), isNull);
    });
  });

  group('PacketReceiver.processPacket', () {
    test('parses frames correctly', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = [
        PingFrame(),
        CryptoFrame(offset: 0, data: [0x01])
      ];
      final packet = await PacketBuilder.build(header, frames);

      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header, isA<LongHeader>());
      expect(result.frames.length, greaterThanOrEqualTo(1));
    });

    test('returns null for unsupported version', () async {
      final header = LongHeader(
        version: 0xDEADBEEF,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = [PingFrame()];
      final packet = await PacketBuilder.build(header, frames);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNull);
    });

    test('returns null for Retry packet', () {
      // Manually build a Retry packet with enough bytes for the parser
      // After DCID/SCID, we need at least 16 more bytes for integrity tag
      final packet = Uint8List.fromList([
        0xF0, // Retry type
        0x00, 0x00, 0x00, 0x01, // version
        0x04, // DCID len = 4
        0xAB, 0xCD, 0xEF, 0x01, // DCID (4 bytes)
        0x04, // SCID len = 4
        0x12, 0x34, 0x56, 0x78, // SCID (4 bytes)
        // Retry token (4 bytes) + integrity tag (16 bytes) = 20 bytes
        0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      ]);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNull);
    });

    test('handles malformed frames gracefully', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final packet = await PacketBuilder.build(header, []);
      // Corrupt the payload with invalid frame bytes
      packet[packet.length - 1] = 0xFF;
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.frames, isEmpty);
    });
  });

  group('PacketReceiver.processDatagram', () {
    test('splits coalesced packets', () async {
      final initial = await PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
          token: const [],
        ),
        [PingFrame()],
      );
      final handshake = await PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeHandshake,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
        ),
        [PingFrame()],
      );

      final datagram = Uint8List(initial.length + handshake.length);
      datagram.setRange(0, initial.length, initial);
      datagram.setRange(initial.length, datagram.length, handshake);

      final results = PacketReceiver.processDatagram(datagram);
      expect(results.length, equals(2));
    });

    test('empty datagram returns empty list', () {
      final results = PacketReceiver.processDatagram(Uint8List(0));
      expect(results, isEmpty);
    });

    test('processes ShortHeader packet', () async {
      final header = ShortHeader(
        destinationConnectionId: [1, 2, 3, 4, 5, 6, 7, 8],
        packetNumber: 0,
        packetNumberLength: 1,
      );
      final packet = await PacketBuilder.build(header, [PingFrame()]);
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header, isA<ShortHeader>());
      expect(result.space, PacketNumberSpace.application);
    });
  });
}

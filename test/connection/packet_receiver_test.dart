import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/connection/packet_receiver.dart';
import 'package:dart_quic/src/wire/packet_header.dart';
import 'package:dart_quic/src/wire/packet_builder.dart';
import 'package:dart_quic/src/wire/frame.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';

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
      expect(PacketReceiver.spaceFromHeader(header), equals(PacketNumberSpace.initial));
    });

    test('Handshake → handshake space', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header), equals(PacketNumberSpace.handshake));
    });

    test('ShortHeader → application space', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
      );
      expect(PacketReceiver.spaceFromHeader(header), equals(PacketNumberSpace.application));
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
  });

  group('PacketReceiver.processPacket', () {
    test('parses frames correctly', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final frames = [PingFrame(), CryptoFrame(offset: 0, data: [0x01])];
      final packet = PacketBuilder.build(header, frames);

      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.header, isA<LongHeader>());
      expect(result.frames.length, greaterThanOrEqualTo(1));
    });
  });

  group('PacketReceiver.processDatagram', () {
    test('splits coalesced packets', () {
      final initial = PacketBuilder.build(
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
      final handshake = PacketBuilder.build(
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
  });
}

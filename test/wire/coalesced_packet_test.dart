import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/wire/coalesced_packet.dart';
import 'package:dart_quic/src/wire/packet_builder.dart';
import 'package:dart_quic/src/wire/packet_header.dart';
import 'package:dart_quic/src/wire/frame.dart';

void main() {
  group('CoalescedPacket.split', () {
    test('splits Initial + Handshake coalesced datagram', () {
      final initial = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
          token: const [],
        ),
        [CryptoFrame(offset: 0, data: [0x01])],
      );
      final handshake = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeHandshake,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
        ),
        [CryptoFrame(offset: 0, data: [0x02])],
      );

      final datagram = Uint8List(initial.length + handshake.length);
      datagram.setRange(0, initial.length, initial);
      datagram.setRange(initial.length, datagram.length, handshake);

      final packets = CoalescedPacket.split(datagram);
      expect(packets.length, equals(2));
      expect(packets[0].length, equals(initial.length));
      expect(packets[1].length, equals(handshake.length));
    });

    test('single long-header packet', () {
      final initial = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
          token: const [],
        ),
        [CryptoFrame(offset: 0, data: [0x01])],
      );

      final packets = CoalescedPacket.split(initial);
      expect(packets.length, equals(1));
      expect(packets[0], equals(initial));
    });

    test('short header consumes remainder', () {
      final short = PacketBuilder.build(
        ShortHeader(
          destinationConnectionId: [0x01],
          packetNumber: 0,
        ),
        [],
      );

      final packets = CoalescedPacket.split(short);
      expect(packets.length, equals(1));
      expect(packets[0], equals(short));
    });
  });

  group('CoalescedPacket.isCoalesced', () {
    test('true for multiple packets', () {
      final initial = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
          token: const [],
        ),
        [CryptoFrame(offset: 0, data: [0x01])],
      );
      final handshake = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeHandshake,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
        ),
        [CryptoFrame(offset: 0, data: [0x02])],
      );

      final datagram = Uint8List(initial.length + handshake.length);
      datagram.setRange(0, initial.length, initial);
      datagram.setRange(initial.length, datagram.length, handshake);

      expect(CoalescedPacket.isCoalesced(datagram), isTrue);
    });

    test('false for single packet', () {
      final initial = PacketBuilder.build(
        LongHeader(
          version: 0x00000001,
          packetType: LongHeader.typeInitial,
          destinationConnectionId: [0x01],
          sourceConnectionId: [0x02],
          packetNumber: 0,
          token: const [],
        ),
        [CryptoFrame(offset: 0, data: [0x01])],
      );

      expect(CoalescedPacket.isCoalesced(initial), isFalse);
    });
  });
}

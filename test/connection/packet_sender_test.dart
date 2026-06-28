import 'package:test/test.dart';
import 'package:quic_lib/src/connection/packet_sender.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';

void main() {
  group('PacketSender.buildPacket', () {
    test('Initial space produces long header', () {
      final bytes = PacketSender.buildPacket(
        frames: [PingFrame()],
        space: PacketNumberSpace.initial,
        dcid: [0x01, 0x02],
        scid: [0x03, 0x04],
        packetNumber: 0,
      );
      expect(bytes[0] & 0x80, isNonZero); // long header form
    });

    test('Handshake space produces long header', () {
      final bytes = PacketSender.buildPacket(
        frames: [PingFrame()],
        space: PacketNumberSpace.handshake,
        dcid: [0x01, 0x02],
        scid: [0x03, 0x04],
        packetNumber: 0,
      );
      expect(bytes[0] & 0x80, isNonZero); // long header form
    });

    test('Application space produces short header', () {
      final bytes = PacketSender.buildPacket(
        frames: [PingFrame()],
        space: PacketNumberSpace.application,
        dcid: [0x01, 0x02],
        packetNumber: 0,
      );
      expect(bytes[0] & 0x80, equals(0)); // short header form
    });

    test('includes frames correctly', () {
      final bytes = PacketSender.buildPacket(
        frames: [
          CryptoFrame(offset: 0, data: [0xAB, 0xCD])
        ],
        space: PacketNumberSpace.initial,
        dcid: [0x01],
        packetNumber: 0,
      );
      expect(bytes.length, greaterThan(10));
    });

    test('small packet does not exceed maxUdpPayloadSize', () {
      final bytes = PacketSender.buildPacket(
        frames: [PingFrame()],
        space: PacketNumberSpace.application,
        dcid: [0x01],
        packetNumber: 0,
      );
      expect(bytes.length, lessThanOrEqualTo(PacketSender.maxUdpPayloadSize));
    });
  });
}

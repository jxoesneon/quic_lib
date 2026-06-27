import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/connection/packet_sender.dart';
import 'package:dart_quic/src/recovery/packet_number_space.dart';
import 'package:dart_quic/src/recovery/sent_packet_tracker.dart';
import 'package:dart_quic/src/wire/packet_builder.dart';
import 'package:dart_quic/src/wire/packet_header.dart';
import 'package:dart_quic/src/wire/frame.dart';

class _EmptyFrame implements Frame {
  @override
  int get frameType => 0xFF;

  @override
  Uint8List serialize() => Uint8List(0);
}

void main() {
  group('PacketBuilder.build coverage', () {
    test('VersionNegotiationPacket returns serialized header', () {
      final header = VersionNegotiationPacket(
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        supportedVersions: [0x00000001, 0x00000002],
      );
      final packet = PacketBuilder.build(header, [PingFrame()]);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header form
      expect(packet[1], equals(0)); // version 0
      expect(packet[2], equals(0));
      expect(packet[3], equals(0));
      expect(packet[4], equals(0));
    });

    test('Retry packet (LongHeader with typeRetry) returns serialized header', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      final packet = PacketBuilder.build(header, [PingFrame()]);
      // Retry should ignore frames and serialize the header
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header form
    });

    test('LongHeader with empty frames list produces valid packet', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header form
    });

    test('multiple frames of different types', () {
      final header = ShortHeader(
        destinationConnectionId: [0xAB],
        packetNumber: 1,
        packetNumberLength: 1,
      );
      final frames = <Frame>[
        PingFrame(),
        PaddingFrame(length: 4),
        CryptoFrame(offset: 0, data: [0x01, 0x02]),
      ];
      final packet = PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, equals(0)); // short header
      // Verify header byte and DCID
      expect(packet[0], equals(0x40)); // short header, no spin bit, PN len 1, no key phase
      expect(packet[1], equals(0xAB));
      expect(packet[2], equals(1)); // packet number
    });

    test('frame with empty serialize() output', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
        packetNumberLength: 1,
      );
      final packet = PacketBuilder.build(header, [_EmptyFrame()]);
      // Should be same as empty frames since the frame produces no bytes
      expect(packet.length, equals(1 + 1 + 1)); // header byte + DCID + PN
    });

    test('very long connection IDs (max 20 bytes)', () {
      final dcid = List<int>.generate(20, (i) => i);
      final scid = List<int>.generate(20, (i) => 20 + i);
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: dcid,
        sourceConnectionId: scid,
        packetNumber: 0,
        token: const [],
      );
      final packet = PacketBuilder.build(header, [PingFrame()]);
      expect(packet.isNotEmpty, isTrue);
      expect(packet[0] & 0x80, isNonZero); // long header
      // DCID length at offset 5 (1 byte first + 4 version)
      expect(packet[5], equals(20));
      // SCID length at offset 5 + 1 + 20 = 26
      expect(packet[26], equals(20));
    });

    test('ShortHeader with packet number length 2', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0x1234,
        packetNumberLength: 2,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.length, equals(1 + 1 + 2));
      expect(packet[0], equals(0x41)); // 0x40 | (2-1) = 0x41
      expect(packet[2], equals(0x12));
      expect(packet[3], equals(0x34));
    });

    test('ShortHeader with packet number length 3', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0x123456,
        packetNumberLength: 3,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.length, equals(1 + 1 + 3));
      expect(packet[0], equals(0x42)); // 0x40 | (3-1) = 0x42
      expect(packet[2], equals(0x12));
      expect(packet[3], equals(0x34));
      expect(packet[4], equals(0x56));
    });

    test('ShortHeader with packet number length 4', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0x12345678,
        packetNumberLength: 4,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.length, equals(1 + 1 + 4));
      expect(packet[0], equals(0x43)); // 0x40 | (4-1) = 0x43
      expect(packet[2], equals(0x12));
      expect(packet[3], equals(0x34));
      expect(packet[4], equals(0x56));
      expect(packet[5], equals(0x78));
    });

    test('ShortHeader with spinBit and keyPhase', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
        packetNumberLength: 1,
        spinBit: true,
        keyPhase: true,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet[0], equals(0x64));
    });
  });

  group('PacketSender coverage', () {
    test('shouldSendPacket with empty frames returns false', () {
      expect(
        PacketSender.shouldSendPacket(PacketNumberSpace.initial, []),
        isFalse,
      );
    });

    test('shouldSendPacket with non-empty frames returns true', () {
      expect(
        PacketSender.shouldSendPacket(PacketNumberSpace.initial, [PingFrame()]),
        isTrue,
      );
    });

    test('trackSentPacket with complete SentPacketInfo', () {
      final tracker = SentPacketTracker();
      final info = SentPacketInfo(
        packetNumber: 42,
        sentTimeUs: 1234567,
        sizeInBytes: 1200,
        ackEliciting: true,
        inFlight: true,
        frames: [0x01],
        space: PacketNumberSpace.application.spaceIndex,
      );
      PacketSender.trackSentPacket(tracker, info);
      final unacked = tracker.getUnackedPackets(PacketNumberSpace.application.spaceIndex);
      expect(unacked.length, equals(1));
      expect(unacked.first.packetNumber, equals(42));
    });

    test('buildPacket with maximum-sized small frames', () {
      // Short header overhead: 1 (first byte) + 1 (dcid) + 1 (pn) = 3
      // maxUdpPayloadSize = 1200, so 1197 PingFrames (1 byte each)
      final frames = List<Frame>.generate(1197, (_) => PingFrame());
      final bytes = PacketSender.buildPacket(
        frames: frames,
        space: PacketNumberSpace.application,
        dcid: [0x01],
        packetNumber: 0,
      );
      expect(bytes.length, equals(1200));
      expect(bytes.length, lessThanOrEqualTo(PacketSender.maxUdpPayloadSize));
    });

    test('maxUdpPayloadSize constant is 1200', () {
      expect(PacketSender.maxUdpPayloadSize, equals(1200));
    });
  });
}

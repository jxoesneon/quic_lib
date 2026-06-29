import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/coalesced_packet.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:test/test.dart';

/// Fuzz/error-path tests for the packet header parser, coalesced packet splitter,
/// and the packet receiver that turns raw datagrams into headers + frames.
///
/// Verifies that malformed/truncated packets are dropped or rejected rather than
/// returning a bogus header or crashing.
void main() {
  group('PacketHeaderParser malformed input', () {
    test('empty packet throws ArgumentError', () {
      expect(
        () => PacketHeaderParser.parse(Uint8List(0),
            destinationConnectionIdLength: 8),
        throwsArgumentError,
      );
    });

    test('truncated long header throws ArgumentError', () {
      // Long header bit set, but no version or CIDs.
      final packet = Uint8List.fromList([0xC0]);
      expect(
        () =>
            PacketHeaderParser.parse(packet, destinationConnectionIdLength: 8),
        throwsArgumentError,
      );
    });

    test('long header with oversized DCID length throws ArgumentError', () {
      final packet = Uint8List.fromList([
        0xC0, // Long header, Initial type
        0x00, 0x00, 0x00, 0x01, // version v1
        0xFF, // DCID length > 20
      ]);
      expect(
        () =>
            PacketHeaderParser.parse(packet, destinationConnectionIdLength: 8),
        throwsArgumentError,
      );
    });

    test('truncated short header throws ArgumentError', () {
      final packet = Uint8List.fromList([
        0x40, // Short header, 1-byte PN
        0x01, 0x02, 0x03, // only 3 bytes of DCID
      ]);
      expect(
        () =>
            PacketHeaderParser.parse(packet, destinationConnectionIdLength: 8),
        throwsArgumentError,
      );
    });

    test('version negotiation parses without throwing', () {
      final packet = Uint8List.fromList([
        0x80, // Long header, version negotiation type
        0x00, 0x00, 0x00, 0x00, // version 0
        0x04, // DCID length 4
        0x01, 0x02, 0x03, 0x04,
        0x04, // SCID length 4
        0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x01, // supported version
      ]);
      final header =
          PacketHeaderParser.parse(packet, destinationConnectionIdLength: 8);
      expect(header, isA<VersionNegotiationPacket>());
    });
  });

  group('CoalescedPacket malformed input', () {
    test('split returns empty list for empty datagram', () {
      expect(CoalescedPacket.split(Uint8List(0)), isEmpty);
    });

    test('split returns empty list for unparseable long header', () {
      final datagram = Uint8List.fromList([
        0xC0, // Long header
        0x00, 0x00, 0x00, 0x01, // version
        0xFF, // DCID length too large
      ]);
      expect(CoalescedPacket.split(datagram), isEmpty);
    });

    test('split treats trailing bytes as short header packet', () {
      final datagram = Uint8List.fromList([
        0x40, // short header
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
        0x00, // PN
        0x01, // PING frame
        0x01, // another PING
      ]);
      final packets = CoalescedPacket.split(datagram);
      expect(packets.length, 1);
      expect(packets[0].length, datagram.length);
    });
  });

  group('PacketReceiver.processPacket malformed input', () {
    test('returns null for empty packet', () {
      expect(PacketReceiver.processPacket(Uint8List(0)), isNull);
    });

    test('returns null for truncated long header', () {
      final packet = Uint8List.fromList([0xC0, 0x00, 0x00, 0x00, 0x01]);
      expect(PacketReceiver.processPacket(packet), isNull);
    });

    test('returns null for unsupported long header version', () async {
      final header = LongHeader(
        version: 0xDEADBEEF,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final packet = await PacketBuilder.build(header, [PingFrame()]);
      expect(PacketReceiver.processPacket(packet), isNull);
    });

    test('returns null for Retry packet', () {
      final packet = Uint8List.fromList([
        0xF0, // Retry
        0x00, 0x00, 0x00, 0x01,
        0x04, 0xAB, 0xCD, 0xEF, 0x01,
        0x04, 0x12, 0x34, 0x56, 0x78,
        0x01, 0x02, 0x03, 0x04,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      ]);
      expect(PacketReceiver.processPacket(packet), isNull);
    });

    test('discards malformed frames from an otherwise valid packet', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final packet = await PacketBuilder.build(header, []);
      // Corrupt the last payload byte with an unknown frame type.
      packet[packet.length - 1] = 0xFF;
      final result = PacketReceiver.processPacket(packet);
      expect(result, isNotNull);
      expect(result!.frames, isEmpty);
      expect(result.space, PacketNumberSpace.initial);
    });
  });

  group('PacketReceiver.processDatagram fuzz tests', () {
    test('empty datagram returns empty list', () {
      expect(PacketReceiver.processDatagram(Uint8List(0)), isEmpty);
    });

    test('random datagrams do not crash', () {
      final random = Random(42);
      for (var i = 0; i < 300; i++) {
        final len = random.nextInt(128) + 1;
        final datagram = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        // Should not throw.
        final results = PacketReceiver.processDatagram(datagram);
        expect(results, isA<List<dynamic>>());
      }
    });

    test('well-formed coalesced datagram is accepted', () async {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0,
        token: const [],
      );
      final packet = await PacketBuilder.build(header, [PingFrame()]);
      final datagram = Uint8List.fromList(packet);
      final results = PacketReceiver.processDatagram(datagram);
      expect(results.length, greaterThanOrEqualTo(1));
      expect(results[0].space, PacketNumberSpace.initial);
    });
  });
}

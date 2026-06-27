import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/wire/packet_header.dart';

void main() {
  group('LongHeader', () {
    test('Initial serialize/parse round-trip', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      final bytes = header.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 3) as LongHeader;
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
      expect(parsed.token, equals(header.token));
    });

    test('0-RTT serialize/parse round-trip', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 100,
        payload: [0xCC],
      );
      final bytes = header.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 1) as LongHeader;
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
    });

    test('Handshake serialize/parse round-trip', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = header.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 1) as LongHeader;
      expect(parsed.packetType, equals(LongHeader.typeHandshake));
    });

    test('Retry serialize/parse round-trip', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      final bytes = header.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 1) as LongHeader;
      expect(parsed.packetType, equals(LongHeader.typeRetry));
      expect(parsed.payload, equals(header.payload));
    });

    test('invalid packet type throws', () {
      expect(
        () => LongHeader(
          version: 1,
          packetType: 7,
          destinationConnectionId: [1],
          sourceConnectionId: [2],
        ),
        throwsArgumentError,
      );
    });

    test('byteLength matches serialized length', () {
      final header = LongHeader(
        version: 1,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [1, 2, 3],
        sourceConnectionId: [4, 5],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      expect(header.byteLength, equals(header.serialize().length));
    });
  });

  group('ShortHeader', () {
    test('serialize/parse round-trip', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        packetNumber: 0x1234,
        spinBit: true,
        keyPhase: true,
        packetNumberLength: 2,
        payload: [0xFF],
      );
      final bytes = header.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 4) as ShortHeader;
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.packetNumber, equals(header.packetNumber));
      expect(parsed.spinBit, equals(header.spinBit));
      expect(parsed.keyPhase, equals(header.keyPhase));
      expect(parsed.packetNumberLength, equals(header.packetNumberLength));
      expect(parsed.payload, equals(header.payload));
    });

    test('minimal short header', () {
      final header = ShortHeader(
        destinationConnectionId: [0x01],
        packetNumber: 0,
        payload: const [],
      );
      final bytes = header.serialize();
      expect(bytes.length, equals(1 + 1 + 1)); // first byte + 1-byte DCID + 1-byte PN
    });

    test('invalid PN length throws', () {
      expect(
        () => ShortHeader(destinationConnectionId: [1], packetNumberLength: 5),
        throwsArgumentError,
      );
    });

    test('byteLength matches serialized length', () {
      final header = ShortHeader(
        destinationConnectionId: [1, 2, 3, 4],
        packetNumber: 0x123456,
        packetNumberLength: 3,
        payload: [0xAA, 0xBB],
      );
      expect(header.byteLength, equals(header.serialize().length));
    });
  });

  group('VersionNegotiationPacket', () {
    test('serialize/parse round-trip', () {
      final packet = VersionNegotiationPacket(
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        supportedVersions: [0x00000001, 0x00000002],
      );
      final bytes = packet.serialize();
      final parsed = PacketHeaderParser.parse(bytes, destinationConnectionIdLength: 1)
          as VersionNegotiationPacket;
      expect(parsed.destinationConnectionId, equals(packet.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(packet.sourceConnectionId));
      expect(parsed.supportedVersions, equals(packet.supportedVersions));
    });

    test('byteLength matches serialized length', () {
      final packet = VersionNegotiationPacket(
        destinationConnectionId: [1, 2],
        sourceConnectionId: [3, 4],
        supportedVersions: [1, 2, 3],
      );
      expect(packet.byteLength, equals(packet.serialize().length));
    });
  });

  group('PacketHeaderParser', () {
    test('empty packet throws', () {
      expect(
        () => PacketHeaderParser.parse(Uint8List(0), destinationConnectionIdLength: 0),
        throwsArgumentError,
      );
    });

    test('too-short packet throws', () {
      expect(
        () => PacketHeaderParser.parse(Uint8List.fromList([0x80]), destinationConnectionIdLength: 0),
        throwsArgumentError,
      );
    });
  });
}

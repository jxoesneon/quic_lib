import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/wire/quic_versions.dart';
import 'package:dart_quic/src/wire/v2_header.dart';

void main() {
  group('V2LongHeader', () {
    test('serialize produces bytes starting with long header form bit', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      final bytes = header.serialize();
      expect(bytes.isNotEmpty, isTrue);
      expect(bytes[0] & 0x80, equals(0x80));
    });

    test('version is v2', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
      );
      expect(header.version, equals(QuicVersions.v2));
    });

    test('packetType 0 (Initial) encodes correctly in first byte', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
      );
      final bytes = header.serialize();
      // v2 first byte: 1 | 1 | 00 | PP | VV
      // PP = 0 (Initial), VV = version & 0x03 = 0x03 for v2 (0x6b3343cf)
      // Expected: 0x80 | 0x40 | 0x00 | 0x03 = 0xC3
      expect(bytes[0], equals(0xC3));
    });

    test('packetType 1 (0-RTT) encodes correctly in first byte', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 1,
        payload: [0xCC],
      );
      final bytes = header.serialize();
      // PP = 1 (0-RTT), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x04 | 0x03 = 0xC7
      expect(bytes[0], equals(0xC7));
    });

    test('packetType 2 (Handshake) encodes correctly in first byte', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = header.serialize();
      // PP = 2 (Handshake), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x08 | 0x03 = 0xCB
      expect(bytes[0], equals(0xCB));
    });

    test('packetType 3 (Retry) encodes correctly in first byte', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      final bytes = header.serialize();
      // PP = 3 (Retry), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x0C | 0x03 = 0xCF
      expect(bytes[0], equals(0xCF));
    });

    test('round-trip: Initial serialize then parse', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      final bytes = header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
      expect(parsed.token, equals(header.token));
    });

    test('round-trip: 0-RTT serialize then parse', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 100,
        payload: [0xCC],
      );
      final bytes = header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
    });

    test('round-trip: Handshake serialize then parse', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.packetType, equals(V2LongHeader.typeHandshake));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
    });

    test('round-trip: Retry serialize then parse', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      final bytes = header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.packetType, equals(V2LongHeader.typeRetry));
      expect(parsed.payload, equals(header.payload));
    });

    test('invalid packet type throws', () {
      expect(
        () => V2LongHeader(
          packetType: 7,
          destinationConnectionId: [1],
          sourceConnectionId: [2],
        ),
        throwsArgumentError,
      );
    });

    test('byteLength matches serialized length', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1, 2, 3],
        sourceConnectionId: [4, 5],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      expect(header.byteLength, equals(header.serialize().length));
    });

    test('parse rejects non-v2 version', () {
      // Manually craft a v1-looking long header with v2 first-byte semantics
      // but version field set to v1 (0x00000001).
      final builder = BytesBuilder();
      // first byte: v2 format, packetType=0, version bits=1
      builder.addByte(0x80 | 0x40 | 0x00 | 0x01);
      // version = v1 (big-endian)
      builder.addByte(0x00);
      builder.addByte(0x00);
      builder.addByte(0x00);
      builder.addByte(0x01);
      // DCID len + DCID
      builder.addByte(1);
      builder.addByte(0xAB);
      // SCID len + SCID
      builder.addByte(1);
      builder.addByte(0xCD);
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });
  });
}

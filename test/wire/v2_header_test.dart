import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/crypto/default_crypto_backend.dart';
import 'package:dart_quic/src/wire/quic_versions.dart';
import 'package:dart_quic/src/wire/v2_header.dart';

void main() {
  group('V2LongHeader', () {
    test('serialize produces bytes starting with long header form bit', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      final bytes = await header.serialize();
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

    test('packetType 0 (Initial) encodes correctly in first byte', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
      );
      final bytes = await header.serialize();
      // v2 first byte: 1 | 1 | 00 | PP | VV
      // PP = 0 (Initial), VV = version & 0x03 = 0x03 for v2 (0x6b3343cf)
      // Expected: 0x80 | 0x40 | 0x00 | 0x03 = 0xC3
      expect(bytes[0], equals(0xC3));
    });

    test('packetType 1 (0-RTT) encodes correctly in first byte', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 1,
        payload: [0xCC],
      );
      final bytes = await header.serialize();
      // PP = 1 (0-RTT), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x04 | 0x03 = 0xC7
      expect(bytes[0], equals(0xC7));
    });

    test('packetType 2 (Handshake) encodes correctly in first byte', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = await header.serialize();
      // PP = 2 (Handshake), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x08 | 0x03 = 0xCB
      expect(bytes[0], equals(0xCB));
    });

    test('packetType 3 (Retry) encodes correctly in first byte', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
        backend: DefaultCryptoBackend(),
      );
      final bytes = await header.serialize();
      // PP = 3 (Retry), VV = 0x03
      // Expected: 0x80 | 0x40 | 0x0C | 0x03 = 0xCF
      expect(bytes[0], equals(0xCF));
    });

    test('round-trip: Initial serialize then parse', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
      expect(parsed.token, equals(header.token));
    });

    test('round-trip: 0-RTT serialize then parse', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 100,
        payload: [0xCC],
      );
      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.version, equals(header.version));
      expect(parsed.packetType, equals(header.packetType));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
    });

    test('round-trip: Handshake serialize then parse', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.packetType, equals(V2LongHeader.typeHandshake));
      expect(parsed.destinationConnectionId, equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
    });

    test('round-trip: Retry serialize then parse', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
        backend: DefaultCryptoBackend(),
      );
      final bytes = await header.serialize();
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

    test('byteLength matches serialized length', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1, 2, 3],
        sourceConnectionId: [4, 5],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      expect(header.byteLength, equals((await header.serialize()).length));
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

    test('parse rejects empty packet', () {
      expect(() => V2LongHeader.parse(Uint8List(0)), throwsArgumentError);
    });

    test('parse rejects short header', () {
      final bytes = Uint8List.fromList([0x40]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects packet too short for version', () {
      final bytes = Uint8List.fromList([0xC3, 0x00, 0x00]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects packet too short for DCID length', () {
      final bytes = Uint8List.fromList([
        0xC3, 0x6b, 0x33, 0x43, 0xcf,
      ]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects packet too short for DCID', () {
      final bytes = Uint8List.fromList([
        0xC3, 0x6b, 0x33, 0x43, 0xcf,
        0x05, // DCID len = 5
        0xAB, // only 1 byte of DCID
      ]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects packet too short for SCID length', () {
      final bytes = Uint8List.fromList([
        0xC3, 0x6b, 0x33, 0x43, 0xcf,
        0x01, 0xAB, // DCID
      ]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects packet too short for SCID', () {
      final bytes = Uint8List.fromList([
        0xC3, 0x6b, 0x33, 0x43, 0xcf,
        0x01, 0xAB, // DCID
        0x02, // SCID len = 2
        0xCD, // only 1 byte of SCID
      ]);
      expect(() => V2LongHeader.parse(bytes), throwsArgumentError);
    });

    test('parse rejects Initial packet too short for token length', () {
      final builder = BytesBuilder();
      builder.addByte(0xC3);
      builder.add([0x6b, 0x33, 0x43, 0xcf]);
      builder.addByte(0x01);
      builder.addByte(0xAB);
      builder.addByte(0x01);
      builder.addByte(0xCD);
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });

    test('parse rejects Initial packet too short for token', () {
      final builder = BytesBuilder();
      builder.addByte(0xC3);
      builder.add([0x6b, 0x33, 0x43, 0xcf]);
      builder.addByte(0x01);
      builder.addByte(0xAB);
      builder.addByte(0x01);
      builder.addByte(0xCD);
      builder.addByte(0x05); // varint token length = 5
      builder.addByte(0x11);
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });

    test('parse rejects Retry packet too short for integrity tag', () {
      final builder = BytesBuilder();
      builder.addByte(0xCF);
      builder.add([0x6b, 0x33, 0x43, 0xcf]);
      builder.addByte(0x01);
      builder.addByte(0xAB);
      builder.addByte(0x01);
      builder.addByte(0xCD);
      builder.addByte(0x11);
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });

    test('parse rejects non-Retry packet too short for length field', () {
      final builder = BytesBuilder();
      builder.addByte(0xC7); // 0-RTT
      builder.add([0x6b, 0x33, 0x43, 0xcf]);
      builder.addByte(0x01);
      builder.addByte(0xAB);
      builder.addByte(0x01);
      builder.addByte(0xCD);
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });

    test('parse rejects non-Retry packet too short for payload', () {
      final builder = BytesBuilder();
      builder.addByte(0xC7); // 0-RTT
      builder.add([0x6b, 0x33, 0x43, 0xcf]);
      builder.addByte(0x01);
      builder.addByte(0xAB);
      builder.addByte(0x01);
      builder.addByte(0xCD);
      builder.addByte(0x10); // varint length = 16
      builder.addByte(0x11); // only 1 byte of payload
      final bytes = builder.toBytes();
      expect(() => V2LongHeader.parse(Uint8List.fromList(bytes)), throwsArgumentError);
    });

    test('serialize Retry without backend throws StateError', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
      );
      expect(header.serialize(), throwsStateError);
    });

    test('isInitial and isRetry getters', () {
      final initial = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
      );
      final retry = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        payload: [0xEE],
        backend: DefaultCryptoBackend(),
      );
      final zeroRtt = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
      );
      expect(initial.isInitial, isTrue);
      expect(initial.isRetry, isFalse);
      expect(retry.isInitial, isFalse);
      expect(retry.isRetry, isTrue);
      expect(zeroRtt.isInitial, isFalse);
      expect(zeroRtt.isRetry, isFalse);
    });

    test('headerForm is 1', () {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
      );
      expect(header.headerForm, equals(1));
    });

    test('constructor rejects negative packet type', () {
      expect(
        () => V2LongHeader(
          packetType: -1,
          destinationConnectionId: [1],
          sourceConnectionId: [2],
        ),
        throwsArgumentError,
      );
    });

    test('constructor rejects DCID longer than 255', () {
      expect(
        () => V2LongHeader(
          packetType: V2LongHeader.typeInitial,
          destinationConnectionId: List<int>.filled(256, 0xFF),
          sourceConnectionId: [2],
        ),
        throwsArgumentError,
      );
    });

    test('constructor rejects SCID longer than 255', () {
      expect(
        () => V2LongHeader(
          packetType: V2LongHeader.typeInitial,
          destinationConnectionId: [1],
          sourceConnectionId: List<int>.filled(256, 0xFF),
        ),
        throwsArgumentError,
      );
    });

    test('Initial with null token serializes correctly', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        token: null,
      );
      final bytes = await header.serialize();
      // token length should be 0 (1-byte varint)
      // First byte: 0xC3, version: 4 bytes, DCID len: 1, DCID: 1, SCID len: 1, SCID: 1
      // token length: 1 (0x00), length field: varint, packet number: 1 (0x00), payload: 0
      expect(bytes.length, greaterThan(0));
      final parsed = V2LongHeader.parse(bytes);
      // Parse always returns a (possibly empty) list for token
      expect(parsed.token, equals(<int>[]));
    });

    test('byteLength for Initial matches serialized length', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1, 2, 3],
        sourceConnectionId: [4, 5],
        packetNumber: 42,
        payload: [0xAA, 0xBB],
        token: [0x99],
      );
      expect(header.byteLength, equals((await header.serialize()).length));
    });

    test('byteLength for 0-RTT matches serialized length', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeZeroRtt,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        packetNumber: 0x1234,
        payload: [0xCC, 0xDD, 0xEE],
      );
      expect(header.byteLength, equals((await header.serialize()).length));
    });

    test('byteLength for Handshake matches serialized length', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        packetNumber: 0xFFFFFF,
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      expect(header.byteLength, equals((await header.serialize()).length));
    });

    test('byteLength for Retry matches serialized length', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: [0x01],
        sourceConnectionId: [0x02],
        payload: [0xEE, 0xFF],
        backend: DefaultCryptoBackend(),
      );
      expect(header.byteLength, equals((await header.serialize()).length));
    });

    test('packet number encoding for boundary values', () async {
      // Test 1-byte PN
      final h1 = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        packetNumber: 0xFF,
        payload: [0xAA],
      );
      final b1 = await h1.serialize();
      expect(b1.length, equals(h1.byteLength));
      final p1 = V2LongHeader.parse(b1);
      expect(p1.payload, equals([0xFF, 0xAA]));

      // Test 2-byte PN
      final h2 = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        packetNumber: 0xFFFF,
        payload: [0xBB],
      );
      final b2 = await h2.serialize();
      expect(b2.length, equals(h2.byteLength));
      final p2 = V2LongHeader.parse(b2);
      expect(p2.payload, equals([0xFF, 0xFF, 0xBB]));

      // Test 3-byte PN
      final h3 = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        packetNumber: 0xFFFFFF,
        payload: [0xCC],
      );
      final b3 = await h3.serialize();
      expect(b3.length, equals(h3.byteLength));
      final p3 = V2LongHeader.parse(b3);
      expect(p3.payload, equals([0xFF, 0xFF, 0xFF, 0xCC]));

      // Test 4-byte PN
      final h4 = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        packetNumber: 0xFFFFFFFF,
        payload: [0xDD],
      );
      final b4 = await h4.serialize();
      expect(b4.length, equals(h4.byteLength));
      final p4 = V2LongHeader.parse(b4);
      expect(p4.payload, equals([0xFF, 0xFF, 0xFF, 0xFF, 0xDD]));

      // Test PN larger than 32-bit to ensure _pnLengthFromValue returns 4
      final h5 = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [1],
        sourceConnectionId: [2],
        packetNumber: 0x100000000,
        payload: [0xEE],
      );
      expect(h5.byteLength, equals((await h5.serialize()).length));
    });
  });
}

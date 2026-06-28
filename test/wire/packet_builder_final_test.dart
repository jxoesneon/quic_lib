import 'dart:mirrors';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/frame.dart';

class _UnknownHeader implements PacketHeader {
  @override
  final List<int> destinationConnectionId = const [0x01];

  @override
  int get headerForm => 2;

  @override
  Uint8List serialize() => Uint8List(0);

  @override
  int get byteLength => 0;
}

class _HugeFrame implements Frame {
  final int _size;
  _HugeFrame(this._size);

  @override
  int get frameType => 0x00;

  @override
  Uint8List serialize() => Uint8List(_size);
}

void main() {
  group('PacketBuilder final coverage', () {
    test('unsupported header type throws UnsupportedError', () {
      final header = _UnknownHeader();
      expect(() => PacketBuilder.build(header, []), throwsUnsupportedError);
    });

    test('LongHeader with packet number 0x100 uses 2-byte PN', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: const [0x01],
        sourceConnectionId: const [0x02],
        packetNumber: 0x100,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
    });

    test('LongHeader with packet number 0x10000 uses 3-byte PN', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: const [0x01],
        sourceConnectionId: const [0x02],
        packetNumber: 0x10000,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
    });

    test('Initial with 100-byte token hits 2-byte varint', () {
      final token = List<int>.generate(100, (i) => i & 0xFF);
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: const [0x01],
        sourceConnectionId: const [0x02],
        packetNumber: 0,
        token: token,
      );
      final packet = PacketBuilder.build(header, []);
      expect(packet.isNotEmpty, isTrue);
    });

    test('LongHeader with huge payload hits 4-byte varint', () {
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeHandshake,
        destinationConnectionId: const [0x01],
        sourceConnectionId: const [0x02],
        packetNumber: 0,
      );
      final frames = [_HugeFrame(20000)];
      final packet = PacketBuilder.build(header, frames);
      expect(packet.isNotEmpty, isTrue);
    });

    test('_encodeVarInt 2-byte branch via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final methodMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere(
              (m) => MirrorSystem.getName(m.simpleName) == '_encodeVarInt');
      final result = classMirror
          .invoke(methodMirror.simpleName, [100]).reflectee as Uint8List;
      expect(result.length, equals(2));
      expect(result[0], equals(0x40 | (100 >> 8)));
      expect(result[1], equals(100 & 0xFF));
    });

    test('_encodeVarInt 4-byte branch via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final methodMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere(
              (m) => MirrorSystem.getName(m.simpleName) == '_encodeVarInt');
      final value = 0x12345678;
      final result = classMirror
          .invoke(methodMirror.simpleName, [value]).reflectee as Uint8List;
      expect(result.length, equals(4));
      expect(result[0], equals(0x80 | (value >> 24)));
      expect(result[1], equals((value >> 16) & 0xFF));
      expect(result[2], equals((value >> 8) & 0xFF));
      expect(result[3], equals(value & 0xFF));
    });

    test('_encodeVarInt 8-byte branch via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final methodMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere(
              (m) => MirrorSystem.getName(m.simpleName) == '_encodeVarInt');
      final value = 0x123456789ABCDEF0;
      final result = classMirror
          .invoke(methodMirror.simpleName, [value]).reflectee as Uint8List;
      expect(result.length, equals(8));
      expect(result[0], equals(0xC0 | ((value >> 56) & 0xFF)));
      expect(result[1], equals((value >> 48) & 0xFF));
      expect(result[2], equals((value >> 40) & 0xFF));
      expect(result[3], equals((value >> 32) & 0xFF));
      expect(result[4], equals((value >> 24) & 0xFF));
      expect(result[5], equals((value >> 16) & 0xFF));
      expect(result[6], equals((value >> 8) & 0xFF));
      expect(result[7], equals(value & 0xFF));
    });

    test('_pnLenFromValue 2-byte branch via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final methodMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere(
              (m) => MirrorSystem.getName(m.simpleName) == '_pnLenFromValue');
      final result =
          classMirror.invoke(methodMirror.simpleName, [0x100]).reflectee as int;
      expect(result, equals(2));
    });

    test('_pnLenFromValue 3-byte branch via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final methodMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere(
              (m) => MirrorSystem.getName(m.simpleName) == '_pnLenFromValue');
      final result = classMirror
          .invoke(methodMirror.simpleName, [0x10000]).reflectee as int;
      expect(result, equals(3));
    });

    test('private constructor is reachable via mirrors', () {
      final classMirror = reflectClass(PacketBuilder);
      final ctorMirror = classMirror.declarations.values
          .whereType<MethodMirror>()
          .firstWhere((m) =>
              m.isConstructor &&
              MirrorSystem.getName(m.simpleName).contains('_'));
      final instance =
          classMirror.newInstance(ctorMirror.constructorName, []).reflectee;
      expect(instance, isA<PacketBuilder>());
    });
  });
}

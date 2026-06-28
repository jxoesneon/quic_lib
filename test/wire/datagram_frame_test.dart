import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('DatagramFrame', () {
    test('serialize 0x30 (no length)', () {
      final data = Uint8List.fromList([0xAB, 0xCD, 0xEF]);
      final frame = DatagramFrame(data: data, hasLength: false);
      expect(frame.frameType, equals(0x30));
      final bytes = frame.serialize();
      expect(bytes[0], equals(0x30));
      expect(bytes.length, equals(1 + data.length));
      expect(bytes.sublist(1), equals(data));
    });

    test('serialize 0x31 (with length)', () {
      final data = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      final frame = DatagramFrame(data: data, hasLength: true);
      expect(frame.frameType, equals(0x31));
      final bytes = frame.serialize();
      expect(bytes[0], equals(0x31));
      // Length is a varint (1 byte for small values)
      expect(bytes.length, equals(1 + 1 + data.length));
      expect(bytes.sublist(2), equals(data));
    });

    test('getByteLength matches serialize length', () {
      final data = Uint8List.fromList([0xAA, 0xBB]);
      final frameNoLen = DatagramFrame(data: data, hasLength: false);
      final frameWithLen = DatagramFrame(data: data, hasLength: true);

      expect(frameNoLen.getByteLength(), equals(frameNoLen.serialize().length));
      expect(frameWithLen.getByteLength(),
          equals(frameWithLen.serialize().length));
    });

    test('getByteLength for large payload uses correct varint size', () {
      final data = Uint8List(300);
      final frame = DatagramFrame(data: data, hasLength: true);
      // 300 requires a 2-byte varint (0x40 prefix + 8 bits)
      expect(frame.getByteLength(), equals(1 + 2 + data.length));
    });
  });

  group('FrameCodec.parse DatagramFrame', () {
    test('round-trip 0x30 (no length)', () {
      final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      final frame = DatagramFrame(data: data, hasLength: false);
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);

      expect(parsed, isA<DatagramFrame>());
      final dg = parsed as DatagramFrame;
      expect(dg.hasLength, isFalse);
      expect(dg.data, equals(data));
      expect(nextOffset, equals(bytes.length));
    });

    test('round-trip 0x31 (with length)', () {
      final data = Uint8List.fromList([0xCA, 0xFE]);
      final frame = DatagramFrame(data: data, hasLength: true);
      final bytes = frame.serialize();
      final (parsed, nextOffset) = FrameCodec.parse(bytes);

      expect(parsed, isA<DatagramFrame>());
      final dg = parsed as DatagramFrame;
      expect(dg.hasLength, isTrue);
      expect(dg.data, equals(data));
      expect(nextOffset, equals(bytes.length));
    });

    test('0x31 allows coalescing (extra bytes after frame)', () {
      final data = Uint8List.fromList([0x11, 0x22]);
      final frame = DatagramFrame(data: data, hasLength: true);
      final frameBytes = frame.serialize();
      // Append trailing bytes (simulating another frame)
      final bytes = Uint8List.fromList([...frameBytes, 0x99, 0x88]);
      final (parsed, nextOffset) = FrameCodec.parse(bytes);

      expect(parsed, isA<DatagramFrame>());
      final dg = parsed as DatagramFrame;
      expect(dg.data, equals(data));
      expect(nextOffset, equals(frameBytes.length));
    });
  });

  group('FrameType enum', () {
    test('datagram value is 0x30', () {
      expect(FrameType.datagram.value, equals(0x30));
    });

    test('datagramWithLength value is 0x31', () {
      expect(FrameType.datagramWithLength.value, equals(0x31));
    });
  });
}

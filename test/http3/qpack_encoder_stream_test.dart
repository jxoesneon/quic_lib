import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_encoder_stream.dart';
import 'package:test/test.dart';

void main() {
  group('EncoderInstruction', () {
    test('InsertWithNameReference round-trip (static)', () {
      final instruction = InsertWithNameReference(
        isStatic: true,
        nameIndex: 5,
        value: 'hello',
      );
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // First bit = 1, second bit = 1 (static)
      expect(bytes[0] & 0xC0, equals(0xC0));

      final parsed = EncoderInstruction.parse(bytes);
      expect(parsed, isA<InsertWithNameReference>());
      final parsedInst = parsed as InsertWithNameReference;
      expect(parsedInst.isStatic, isTrue);
      expect(parsedInst.nameIndex, equals(5));
      expect(parsedInst.value, equals('hello'));
    });

    test('InsertWithNameReference round-trip (dynamic)', () {
      final instruction = InsertWithNameReference(
        isStatic: false,
        nameIndex: 3,
        value: 'world',
      );
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // First bit = 1, second bit = 0 (dynamic)
      expect(bytes[0] & 0xC0, equals(0x80));

      final parsed = EncoderInstruction.parse(bytes);
      expect(parsed, isA<InsertWithNameReference>());
      final parsedInst = parsed as InsertWithNameReference;
      expect(parsedInst.isStatic, isFalse);
      expect(parsedInst.nameIndex, equals(3));
      expect(parsedInst.value, equals('world'));
    });

    test('InsertWithNameReference with large nameIndex', () {
      final instruction = InsertWithNameReference(
        isStatic: true,
        nameIndex: 100,
        value: 'test',
      );
      final bytes = instruction.serialize();
      final parsed = EncoderInstruction.parse(bytes);
      expect((parsed as InsertWithNameReference).nameIndex, equals(100));
    });

    test('InsertWithoutNameReference round-trip', () {
      final instruction = InsertWithoutNameReference(
        name: 'custom-key',
        value: 'custom-value',
      );
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // First two bits = 01
      expect(bytes[0] & 0xC0, equals(0x40));

      final parsed = EncoderInstruction.parse(bytes);
      expect(parsed, isA<InsertWithoutNameReference>());
      final parsedInst = parsed as InsertWithoutNameReference;
      expect(parsedInst.name, equals('custom-key'));
      expect(parsedInst.value, equals('custom-value'));
    });

    test('Duplicate round-trip', () {
      final instruction = Duplicate(index: 7);
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // First three bits = 000
      expect(bytes[0] & 0xE0, equals(0x00));

      final parsed = EncoderInstruction.parse(bytes);
      expect(parsed, isA<Duplicate>());
      expect((parsed as Duplicate).index, equals(7));
    });

    test('Duplicate with large index', () {
      final instruction = Duplicate(index: 500);
      final bytes = instruction.serialize();
      final parsed = EncoderInstruction.parse(bytes);
      expect((parsed as Duplicate).index, equals(500));
    });

    test('SetDynamicTableCapacity round-trip', () {
      final instruction = SetDynamicTableCapacity(capacity: 4096);
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // First three bits = 001
      expect(bytes[0] & 0xE0, equals(0x20));

      final parsed = EncoderInstruction.parse(bytes);
      expect(parsed, isA<SetDynamicTableCapacity>());
      expect((parsed as SetDynamicTableCapacity).capacity, equals(4096));
    });

    test('SetDynamicTableCapacity with large capacity', () {
      final instruction = SetDynamicTableCapacity(capacity: 10000);
      final bytes = instruction.serialize();
      final parsed = EncoderInstruction.parse(bytes);
      expect((parsed as SetDynamicTableCapacity).capacity, equals(10000));
    });

    test('parse rejects empty bytes', () {
      expect(
        () => EncoderInstruction.parse(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('parse rejects unknown instruction prefix', () {
      // 111xxxxx is not a valid encoder instruction prefix.
      expect(
        () => EncoderInstruction.parse(Uint8List.fromList([0xFF])),
        throwsArgumentError,
      );
    });
  });
}

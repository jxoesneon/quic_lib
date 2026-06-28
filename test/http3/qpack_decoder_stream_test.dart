import 'dart:typed_data';

import 'package:quic_lib/src/http3/qpack_decoder_stream.dart';
import 'package:test/test.dart';

void main() {
  group('DecoderInstruction.parse', () {
    test('parses SectionAcknowledgment (T = 1, 7-bit prefix)', () {
      final bytes = SectionAcknowledgment(streamId: 42).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<SectionAcknowledgment>());
      expect((parsed as SectionAcknowledgment).streamId, equals(42));
    });

    test('parses StreamCancellation (T = 01, 6-bit prefix)', () {
      final bytes = StreamCancellation(streamId: 99).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<StreamCancellation>());
      expect((parsed as StreamCancellation).streamId, equals(99));
    });

    test('parses InsertCountIncrement (T = 00, 6-bit prefix)', () {
      final bytes = InsertCountIncrement(increment: 7).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<InsertCountIncrement>());
      expect((parsed as InsertCountIncrement).increment, equals(7));
    });

    test('rejects empty byte buffer', () {
      expect(
        () => DecoderInstruction.parse(Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('parses SectionAcknowledgment with large streamId', () {
      final bytes = SectionAcknowledgment(streamId: 500).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<SectionAcknowledgment>());
      expect((parsed as SectionAcknowledgment).streamId, equals(500));
    });

    test('parses StreamCancellation with large streamId', () {
      final bytes = StreamCancellation(streamId: 1000).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<StreamCancellation>());
      expect((parsed as StreamCancellation).streamId, equals(1000));
    });

    test('parses InsertCountIncrement with large increment', () {
      final bytes = InsertCountIncrement(increment: 2000).serialize();
      final parsed = DecoderInstruction.parse(bytes);

      expect(parsed, isA<InsertCountIncrement>());
      expect((parsed as InsertCountIncrement).increment, equals(2000));
    });
  });

  group('SectionAcknowledgment', () {
    test('serialize round-trip preserves streamId', () {
      final instruction = SectionAcknowledgment(streamId: 0);
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // Top bit must be 1.
      expect(bytes[0] & 0x80, equals(0x80));

      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as SectionAcknowledgment).streamId, equals(0));
    });

    test('serialize round-trip with non-zero streamId', () {
      final instruction = SectionAcknowledgment(streamId: 63);
      final bytes = instruction.serialize();
      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as SectionAcknowledgment).streamId, equals(63));
    });
  });

  group('StreamCancellation', () {
    test('serialize round-trip preserves streamId', () {
      final instruction = StreamCancellation(streamId: 0);
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // Top two bits must be 01.
      expect(bytes[0] & 0xC0, equals(0x40));

      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as StreamCancellation).streamId, equals(0));
    });

    test('serialize round-trip with non-zero streamId', () {
      final instruction = StreamCancellation(streamId: 31);
      final bytes = instruction.serialize();
      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as StreamCancellation).streamId, equals(31));
    });
  });

  group('InsertCountIncrement', () {
    test('serialize round-trip preserves increment', () {
      final instruction = InsertCountIncrement(increment: 0);
      final bytes = instruction.serialize();
      expect(bytes.isNotEmpty, isTrue);
      // Top two bits must be 00.
      expect(bytes[0] & 0xC0, equals(0x00));

      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as InsertCountIncrement).increment, equals(0));
    });

    test('serialize round-trip with non-zero increment', () {
      final instruction = InsertCountIncrement(increment: 15);
      final bytes = instruction.serialize();
      final parsed = DecoderInstruction.parse(bytes);
      expect((parsed as InsertCountIncrement).increment, equals(15));
    });
  });
}

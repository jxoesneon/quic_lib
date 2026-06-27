import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/streams/reassembly_buffer.dart';

void main() {
  group('ReassemblyBuffer', () {
    test('in-order insertion read immediately', () {
      final buf = ReassemblyBuffer();
      buf.insert(0, [0x01, 0x02]);
      final data = buf.read();
      expect(data, equals(Uint8List.fromList([0x01, 0x02])));
      expect(buf.readOffset, equals(2));
    });

    test('out-of-order insertion waits for gap fill', () {
      final buf = ReassemblyBuffer();
      buf.insert(4, [0x05, 0x06]);
      expect(buf.read(), isNull);
      buf.insert(0, [0x01, 0x02, 0x03, 0x04]);
      final data = buf.read();
      expect(data, equals(Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])));
    });

    test('final size triggers completion', () {
      final buf = ReassemblyBuffer();
      buf.insert(0, [0x01, 0x02]);
      buf.finalSize = 2;
      buf.read();
      expect(buf.isComplete, isTrue);
    });

    test('reset clears state', () {
      final buf = ReassemblyBuffer();
      buf.insert(0, [0x01]);
      buf.read();
      buf.reset();
      expect(buf.readOffset, equals(0));
      expect(buf.isComplete, isFalse);
    });

    test('hasGaps', () {
      final buf = ReassemblyBuffer();
      expect(buf.hasGaps, isFalse);
      buf.insert(4, [0x01]);
      expect(buf.hasGaps, isTrue);
      buf.insert(0, [0x00, 0x00, 0x00, 0x00]);
      buf.read(); // consume contiguous bytes
      expect(buf.hasGaps, isFalse);
    });
  });
}

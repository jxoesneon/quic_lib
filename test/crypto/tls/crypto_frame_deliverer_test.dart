import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/crypto_frame_deliverer.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  late CryptoFrameDeliverer deliverer;

  setUp(() {
    deliverer = CryptoFrameDeliverer();
  });

  group('CryptoFrameDeliverer', () {
    test('small message fits in one frame', () {
      final message = Uint8List.fromList(List.generate(100, (i) => i));
      final frames = deliverer.chunk(message);

      expect(frames.length, equals(1));
      expect(frames[0].offset, equals(0));
      expect(frames[0].data.length, equals(100));
      expect(frames[0].data, equals(message));
      expect(deliverer.writeOffset, equals(100));
    });

    test('large message chunked correctly', () {
      final message = Uint8List.fromList(List.generate(2500, (i) => i % 256));
      final frames = deliverer.chunk(message, maxFrameSize: 1200);

      expect(frames.length, equals(3));
      expect(frames[0].data.length, equals(1200));
      expect(frames[1].data.length, equals(1200));
      expect(frames[2].data.length, equals(100));
    });

    test('sequential offsets', () {
      final message = Uint8List.fromList(List.generate(2500, (i) => i % 256));
      final frames = deliverer.chunk(message, maxFrameSize: 1200);

      expect(frames[0].offset, equals(0));
      expect(frames[1].offset, equals(1200));
      expect(frames[2].offset, equals(2400));
      expect(deliverer.writeOffset, equals(2500));
    });

    test('reset clears state', () {
      final message = Uint8List.fromList(List.generate(100, (i) => i));
      deliverer.chunk(message);
      expect(deliverer.writeOffset, equals(100));

      deliverer.reset();
      expect(deliverer.writeOffset, equals(0));

      final message2 = Uint8List.fromList(List.generate(50, (i) => i + 1));
      final frames = deliverer.chunk(message2);

      expect(frames[0].offset, equals(0));
      expect(deliverer.writeOffset, equals(50));
    });
  });
}

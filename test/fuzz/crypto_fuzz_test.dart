import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/wire/frame.dart';

void _fillBytes(Random rng, Uint8List bytes) {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = rng.nextInt(256);
  }
}

void main() {
  final rng = Random.secure();

  group('Frame fuzz', () {
    test('random bytes do not crash frame codec', () {
      for (var i = 0; i < 100; i++) {
        final bytes = Uint8List(rng.nextInt(256));
        _fillBytes(rng, bytes);
        try {
          FrameCodec.parse(bytes);
        } catch (_) {
          // Expected for invalid frames
        }
      }
    });
  });
}

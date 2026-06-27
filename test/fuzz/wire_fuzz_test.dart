import 'dart:math';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:dart_quic/src/wire/varint.dart';
import 'package:dart_quic/src/wire/packet_header.dart';

void _fillBytes(Random rng, Uint8List bytes) {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = rng.nextInt(256);
  }
}

void main() {
  final rng = Random.secure();

  group('VarInt fuzz', () {
    test('encode/decode round-trip for random values', () {
      for (var i = 0; i < 1000; i++) {
        // Random.nextInt is limited to 2^32, so build a 62-bit value from
        // two parts to cover the full VarInt range.
        final high = rng.nextInt(1 << 30); // 30 bits
        final low = rng.nextInt(1 << 32);  // 32 bits
        final value = (high << 32) | low;
        final encoded = VarInt.encode(value);
        final decoded = VarInt.decode(encoded.buffer);
        expect(decoded, equals(value));
      }
    });
  });

  group('PacketHeader fuzz', () {
    test('random short headers do not crash parser', () {
      for (var i = 0; i < 100; i++) {
        final bytes = Uint8List(1 + rng.nextInt(255));
        _fillBytes(rng, bytes);
        bytes[0] = 0x40 | (bytes[0] & 0x3F); // Ensure short header form
        try {
          PacketHeaderParser.parse(
            bytes,
            destinationConnectionIdLength: rng.nextInt(256),
          );
        } catch (_) {
          // Expected for invalid packets
        }
      }
    });
  });
}

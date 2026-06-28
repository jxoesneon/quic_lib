import 'package:test/test.dart';
import 'package:quic_lib/src/wire/packet_number.dart';

void main() {
  group('PacketNumber.encode', () {
    test('encodes 0 in 1 byte', () {
      expect(PacketNumber.encode(0, 1), equals([0x00]));
    });

    test('encodes 42 in 1 byte', () {
      expect(PacketNumber.encode(42, 1), equals([0x2a]));
    });

    test('encodes 0x1234 in 2 bytes', () {
      expect(PacketNumber.encode(0x1234, 2), equals([0x12, 0x34]));
    });

    test('encodes 0x123456 in 3 bytes', () {
      expect(PacketNumber.encode(0x123456, 3), equals([0x12, 0x34, 0x56]));
    });

    test('encodes 0x12345678 in 4 bytes', () {
      expect(
          PacketNumber.encode(0x12345678, 4), equals([0x12, 0x34, 0x56, 0x78]));
    });

    test('invalid length throws', () {
      expect(() => PacketNumber.encode(0, 0), throwsArgumentError);
      expect(() => PacketNumber.encode(0, 5), throwsArgumentError);
    });
  });

  group('PacketNumber.reconstruct', () {
    test('reconstructs same window', () {
      final pn = PacketNumber.reconstruct(0x2a, 8, 100);
      expect(pn, equals(0x2a));
    });

    test('reconstructs after wrap', () {
      // largestAcked = 250, truncated = 10 with 8 bits
      // window = 256, half = 128
      // candidate = (250 & ~255) | 10 = 0 | 10 = 10
      // 10 <= 250 - 128 = 122 → candidate += 256 = 266
      final pn = PacketNumber.reconstruct(10, 8, 250);
      expect(pn, equals(266));
    });

    test('reconstructs before wrap', () {
      // largestAcked = 300, truncated = 250 with 8 bits
      // window = 256, half = 128
      // candidate = (300 & ~255) | 250 = 256 | 250 = 506
      // 506 > 300 + 128 = 428 → candidate -= 256 = 250
      final pn = PacketNumber.reconstruct(250, 8, 300);
      expect(pn, equals(250));
    });

    test('reconstructs with 16 bits', () {
      // 0x1234 with largestAcked=0x10000 wraps forward by one window
      final pn = PacketNumber.reconstruct(0x1234, 16, 0x10000);
      expect(pn, equals(0x11234)); // 4660 + 65536 = 70196
    });

    test('reconstructs large gap with 32 bits', () {
      final pn = PacketNumber.reconstruct(0xABCDEF00, 32, 0xFFFFFFFF);
      expect(pn, equals(0xABCDEF00));
    });
  });

  group('PacketNumber.minEncodingLength', () {
    test('1 byte sufficient when close to largestAcked', () {
      expect(PacketNumber.minEncodingLength(100, 100), equals(1));
    });

    test('needs 2 bytes when gap exceeds 1-byte window', () {
      expect(PacketNumber.minEncodingLength(300, 100), equals(2));
    });

    test('always returns at most 4', () {
      expect(PacketNumber.minEncodingLength(0x12345678, 0), equals(4));
    });
  });
}

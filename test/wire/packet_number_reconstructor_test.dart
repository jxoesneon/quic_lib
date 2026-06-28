import 'package:test/test.dart';
import 'package:quic_lib/src/wire/packet_number_reconstructor.dart';

void main() {
  group('PacketNumberReconstructor', () {
    test('reconstructs PN 0xAB when largest is 0xFF and truncated to 1 byte',
        () {
      expect(reconstruct(0xAB, 8, 0xFF), 0xAB);
    });

    test(
        'reconstructs PN 0x1234 when largest is 0x1200 and truncated to 2 bytes',
        () {
      expect(reconstruct(0x1234, 16, 0x1200), 0x1234);
    });

    test(
        'reconstructs wrapped PN (largest=0xFE, truncated=0x01, 1 byte) → 0x101',
        () {
      expect(reconstruct(0x01, 8, 0xFE), 0x101);
    });

    test('truncate and reconstruct is identity for values within window', () {
      const largestReceived = 0x1000;
      // Values strictly within the reconstructible half-window on either side.
      for (var offset = -127; offset <= 128; offset++) {
        final packetNumber = largestReceived + 1 + offset;
        final truncated = truncate(packetNumber, 1);
        final reconstructed = reconstruct(truncated, 8, largestReceived);
        expect(reconstructed, packetNumber,
            reason:
                'Failed for packetNumber=0x${packetNumber.toRadixString(16)}, offset=$offset');
      }
    });

    test('truncate throws for invalid numBytes', () {
      expect(() => truncate(0, 0), throwsA(isA<ArgumentError>()));
      expect(() => truncate(0, 5), throwsA(isA<ArgumentError>()));
    });
  });
}

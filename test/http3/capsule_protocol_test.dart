import 'dart:typed_data';

import 'package:quic_lib/src/http3/capsule_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('CapsuleProtocol', () {
    test('DatagramCapsule serialize/parse round-trip', () {
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final capsule = DatagramCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<DatagramCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('CloseWebTransportSessionCapsule round-trip', () {
      final data = Uint8List.fromList([0x00, 0x00, 0x00, 0x42]);
      final capsule = CloseWebTransportSessionCapsule(data: data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<CloseWebTransportSessionCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('DrainWebTransportSessionCapsule round-trip', () {
      final data = Uint8List.fromList([0xAB, 0xCD]);
      final capsule = DrainWebTransportSessionCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<DrainWebTransportSessionCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('GoawayCapsule round-trip', () {
      final data = Uint8List.fromList([0x00, 0x00, 0x00, 0x00]);
      final capsule = GoawayCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<GoawayCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('parse at offset skips leading bytes', () {
      final capsule = DatagramCapsule(Uint8List.fromList([0xFF]));
      final bytes = capsule.serialize();
      final prefixed = Uint8List.fromList([0xAA, 0xBB, ...bytes]);

      final (parsed, consumed) = Capsule.parse(prefixed, offset: 2);
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('RegisterBidirectionalStreamCapsule round-trip', () {
      final data = Uint8List.fromList([0x08]);
      final capsule = RegisterBidirectionalStreamCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<RegisterBidirectionalStreamCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('RegisterUnidirectionalStreamCapsule round-trip', () {
      final data = Uint8List.fromList([0x0C]);
      final capsule = RegisterUnidirectionalStreamCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<RegisterUnidirectionalStreamCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('parse throws for unknown capsule type', () {
      // Build an unknown capsule manually: type 0x99, length 0, no data.
      final unknown = Uint8List.fromList([0x99, 0x00]);
      expect(() => Capsule.parse(unknown), throwsArgumentError);
    });

    test('parse throws for truncated data', () {
      // Datagram type 0x00, length 5, but only 2 bytes of data.
      final truncated = Uint8List.fromList([0x00, 0x05, 0x01, 0x02]);
      expect(() => Capsule.parse(truncated), throwsArgumentError);
    });
  });
}

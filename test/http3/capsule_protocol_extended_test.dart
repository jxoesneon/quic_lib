import 'dart:typed_data';

import 'package:quic_lib/src/http3/capsule_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('CapsuleProtocolExtended', () {
    test('DatagramCapsule serialize/parse round-trip', () {
      final data = Uint8List.fromList([1, 2, 3, 4]);
      final capsule = DatagramCapsule(data);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<DatagramCapsule>());
      expect(parsed, equals(capsule));
      expect(consumed, equals(bytes.length));
    });

    test('CloseWebTransportSessionCapsule round-trip with error message', () {
      final capsule = CloseWebTransportSessionCapsule(
        errorCode: 42,
        errorMessage: 'session closed',
      );
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<CloseWebTransportSessionCapsule>());
      final wtParsed = parsed as CloseWebTransportSessionCapsule;
      expect(wtParsed.errorCode, equals(42));
      expect(wtParsed.errorMessage, equals('session closed'));
      expect(consumed, equals(bytes.length));
    });

    test('CloseWebTransportSessionCapsule round-trip without message', () {
      final capsule = CloseWebTransportSessionCapsule(errorCode: 0);
      final bytes = capsule.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(parsed, isA<CloseWebTransportSessionCapsule>());
      final wtParsed = parsed as CloseWebTransportSessionCapsule;
      expect(wtParsed.errorCode, equals(0));
      expect(wtParsed.errorMessage, isNull);
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

    test('parse throws for truncated data', () {
      // Datagram type 0x00, length 5, but only 2 bytes of data.
      final truncated = Uint8List.fromList([0x00, 0x05, 0x01, 0x02]);
      expect(() => Capsule.parse(truncated), throwsArgumentError);
    });

    test('parse throws for buffer too short for type', () {
      final short = Uint8List.fromList([0x80]);
      expect(() => Capsule.parse(short), throwsArgumentError);
    });

    test('parse throws for buffer too short for length', () {
      final short = Uint8List.fromList([0x00]);
      expect(() => Capsule.parse(short), throwsArgumentError);
    });
  });
}

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';

import '../helpers/hex.dart';

void main() {
  group('CapsuleType', () {
    test('fromValue returns correct enum for known types', () {
      expect(
        CapsuleType.fromValue(0x1a4),
        equals(CapsuleType.closeWebTransportSession),
      );
      expect(
        CapsuleType.fromValue(0x78ae),
        equals(CapsuleType.drainWebTransportSession),
      );
      expect(CapsuleType.fromValue(0x1b), equals(CapsuleType.grease0));
      expect(CapsuleType.fromValue(0x2a), equals(CapsuleType.grease1));
    });

    test('fromValue returns null for unknown type', () {
      expect(CapsuleType.fromValue(0x9999), isNull);
    });
  });

  group('Capsule', () {
    test('serialize produces valid bytes', () {
      final capsule = Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: hexDecode('dead beef'),
      );
      final bytes = capsule.serialize();
      // type = 0x1a4 -> 2-byte varint: 0x41 0xa4
      // length = 4 -> 1-byte varint: 0x04
      // payload: de ad be ef
      expect(bytes, equals(hexDecode('41 a4 04 de ad be ef')));
    });

    test('parse round-trip', () {
      final original = Capsule(
        type: CapsuleType.drainWebTransportSession,
        payload: hexDecode('01 02 03 04 05'),
      );
      final bytes = original.serialize();
      final (parsed, consumed) = Capsule.parse(bytes);

      expect(consumed, equals(bytes.length));
      expect(parsed.type, equals(original.type));
      expect(parsed.payload, equals(original.payload));
    });

    test('different capsule types preserved', () {
      final closeCapsule = Capsule(
        type: CapsuleType.closeWebTransportSession,
        payload: Uint8List(0),
      );
      final drainCapsule = Capsule(
        type: CapsuleType.drainWebTransportSession,
        payload: Uint8List(0),
      );

      final closeBytes = closeCapsule.serialize();
      final drainBytes = drainCapsule.serialize();

      final (parsedClose, _) = Capsule.parse(closeBytes);
      final (parsedDrain, _) = Capsule.parse(drainBytes);

      expect(
        parsedClose.type,
        equals(CapsuleType.closeWebTransportSession),
      );
      expect(
        parsedDrain.type,
        equals(CapsuleType.drainWebTransportSession),
      );
      expect(parsedClose.type, isNot(equals(parsedDrain.type)));
    });

    test('empty payload works', () {
      final capsule = Capsule(
        type: CapsuleType.grease0,
        payload: <int>[],
      );
      final bytes = capsule.serialize();
      // type = 0x1b -> 1-byte varint: 0x1b
      // length = 0 -> 1-byte varint: 0x00
      expect(bytes, equals(hexDecode('1b 00')));

      final (parsed, consumed) = Capsule.parse(bytes);
      expect(consumed, equals(2));
      expect(parsed.type, equals(CapsuleType.grease0));
      expect(parsed.payload, isEmpty);
    });

    test('parse with offset works', () {
      final prefix = hexDecode('ff ff');
      final capsule = Capsule(
        type: CapsuleType.grease1,
        payload: hexDecode('aa bb'),
      );
      final bytes = Uint8List.fromList([
        ...prefix,
        ...capsule.serialize(),
      ]);

      final (parsed, consumed) = Capsule.parse(bytes, offset: 2);
      expect(consumed, equals(capsule.serialize().length));
      expect(parsed.type, equals(CapsuleType.grease1));
      expect(parsed.payload, equals(hexDecode('aa bb')));
    });

    test('parse throws for truncated buffer', () {
      final bytes = hexDecode(
        '1b 05 01 02',
      ); // claims length 5, only 2 payload bytes
      expect(
        () => Capsule.parse(Uint8List.fromList(bytes)),
        throwsArgumentError,
      );
    });

    test('parse throws for unknown capsule type', () {
      // type 0x3fff (unknown, 2-byte varint), length 0
      final bytes = hexDecode('bf ff 00');
      expect(
        () => Capsule.parse(Uint8List.fromList(bytes)),
        throwsArgumentError,
      );
    });
  });
}

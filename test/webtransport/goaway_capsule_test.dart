import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/webtransport/goaway_capsule.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';

void main() {
  group('GoawayCapsule', () {
    test('serialize/parse round-trip with streamId', () {
      final original = GoawayCapsule(streamId: 42);
      final bytes = original.serialize();
      final parsed = GoawayCapsule.parse(bytes);

      expect(parsed.streamId, equals(42));
      expect(parsed, equals(original));
    });

    test('serialize/parse round-trip without streamId', () {
      final original = GoawayCapsule();
      final bytes = original.serialize();
      final parsed = GoawayCapsule.parse(bytes);

      expect(parsed.streamId, isNull);
      expect(parsed, equals(original));
    });

    test('toString includes streamId', () {
      final capsule = GoawayCapsule(streamId: 42);
      expect(capsule.toString(), contains('42'));
    });

    test('toString with null streamId', () {
      final capsule = GoawayCapsule();
      expect(capsule.toString(), contains('null'));
    });

    test('hashCode is consistent', () {
      final a = GoawayCapsule(streamId: 42);
      final b = GoawayCapsule(streamId: 42);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('equals returns false for non-GoawayCapsule', () {
      final capsule = GoawayCapsule(streamId: 42);
      expect(capsule == 'not a capsule', isFalse);
    });

    test('equals returns false for different streamId', () {
      final a = GoawayCapsule(streamId: 1);
      final b = GoawayCapsule(streamId: 2);
      expect(a == b, isFalse);
    });

    test('equals returns true for identical instance', () {
      final capsule = GoawayCapsule(streamId: 42);
      expect(capsule == capsule, isTrue);
    });

    test('serialize with large streamId uses multi-byte varint', () {
      final capsule = GoawayCapsule(streamId: 1000);
      final bytes = capsule.serialize();
      // Type (0x1d = 1 byte) + streamId (1000 = 2 bytes) = 3 bytes total.
      expect(bytes.length, equals(3));
      final parsed = GoawayCapsule.parse(bytes);
      expect(parsed.streamId, equals(1000));
    });

    test('parse with multi-byte type varint and no streamId', () {
      // Manually encode type 0x1d as a 2-byte varint: [0x40, 0x1d].
      final bytes = Uint8List.fromList([0x40, 0x1d]);
      final parsed = GoawayCapsule.parse(bytes);
      expect(parsed.streamId, isNull);
    });

    test('parse with multi-byte type varint and streamId', () {
      // Type 0x1d as 2-byte varint + streamId 42 as 1-byte varint.
      final bytes = Uint8List.fromList([0x40, 0x1d, 0x2a]);
      final parsed = GoawayCapsule.parse(bytes);
      expect(parsed.streamId, equals(42));
    });
  });

  group('WebTransportSession receives goaway capsule', () {
    test('sets receivedGoaway when goaway capsule is received', () {
      final session = WebTransportSession(1);
      expect(session.receivedGoaway, isFalse);

      // Build a GOAWAY capsule with an optional stream ID.
      final goaway = GoawayCapsule(streamId: 10);
      final capsule = Capsule(
        type: CapsuleType.goaway,
        payload:
            Uint8List.sublistView(goaway.serialize(), 1), // strip type varint
      );

      session.onCapsuleReceived(capsule);
      expect(session.receivedGoaway, isTrue);
    });
  });
}

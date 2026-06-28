import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/webtransport/goaway_capsule.dart';
import 'package:dart_quic/src/webtransport/capsule_types.dart';
import 'package:dart_quic/src/webtransport/webtransport_session.dart';

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
  });

  group('WebTransportSession receives goaway capsule', () {
    test('sets receivedGoaway when goaway capsule is received', () {
      final session = WebTransportSession(1);
      expect(session.receivedGoaway, isFalse);

      // Build a GOAWAY capsule with an optional stream ID.
      final goaway = GoawayCapsule(streamId: 10);
      final capsule = Capsule(
        type: CapsuleType.goaway,
        payload: Uint8List.sublistView(goaway.serialize(), 1), // strip type varint
      );

      session.onCapsuleReceived(capsule);
      expect(session.receivedGoaway, isTrue);
    });
  });
}

import 'dart:typed_data';

import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/stream_capsule.dart';
import 'package:quic_lib/src/webtransport/webtransport_session.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:test/test.dart';

void main() {
  group('StreamCapsule', () {
    test('serialize/parse round-trip for bidirectional', () {
      final original = StreamCapsule(
        streamId: 42,
        type: CapsuleType.registerBidirectionalStream,
      );
      final bytes = original.serialize();
      final parsed = StreamCapsule.parse(bytes);

      expect(parsed, equals(original));
      expect(parsed.streamId, equals(42));
      expect(parsed.type, equals(CapsuleType.registerBidirectionalStream));
    });

    test('serialize/parse round-trip for unidirectional', () {
      final original = StreamCapsule(
        streamId: 100,
        type: CapsuleType.registerUnidirectionalStream,
      );
      final bytes = original.serialize();
      final parsed = StreamCapsule.parse(bytes);

      expect(parsed, equals(original));
      expect(parsed.streamId, equals(100));
      expect(parsed.type, equals(CapsuleType.registerUnidirectionalStream));
    });
  });

  group('WebTransportSession stream tracking', () {
    test('tracks registered bidirectional streams', () {
      final session = WebTransportSession(1);
      final capsule = Capsule(
        type: CapsuleType.registerBidirectionalStream,
        payload: VarInt.encode(8),
      );

      session.onCapsuleReceived(capsule);

      expect(session.registeredBidirectionalStreams, contains(8));
      expect(session.registeredBidirectionalStreams.length, equals(1));
    });

    test('tracks registered unidirectional streams', () {
      final session = WebTransportSession(1);
      final capsule = Capsule(
        type: CapsuleType.registerUnidirectionalStream,
        payload: VarInt.encode(12),
      );

      session.onCapsuleReceived(capsule);

      expect(session.registeredUnidirectionalStreams, contains(12));
      expect(session.registeredUnidirectionalStreams.length, equals(1));
    });
  });
}

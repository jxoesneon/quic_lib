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

    test('toString includes streamId and type', () {
      final capsule = StreamCapsule(
        streamId: 42,
        type: CapsuleType.registerBidirectionalStream,
      );
      expect(capsule.toString(), contains('42'));
      expect(capsule.toString(), contains('registerBidirectionalStream'));
    });

    test('hashCode is consistent', () {
      final a = StreamCapsule(
          streamId: 42, type: CapsuleType.registerBidirectionalStream);
      final b = StreamCapsule(
          streamId: 42, type: CapsuleType.registerBidirectionalStream);
      expect(a.hashCode, equals(b.hashCode));
    });

    test('equals returns false for non-StreamCapsule', () {
      final capsule = StreamCapsule(
          streamId: 42, type: CapsuleType.registerBidirectionalStream);
      expect(capsule == 'not a capsule', isFalse);
    });

    test('equals returns false for different streamId', () {
      final a = StreamCapsule(
          streamId: 1, type: CapsuleType.registerBidirectionalStream);
      final b = StreamCapsule(
          streamId: 2, type: CapsuleType.registerBidirectionalStream);
      expect(a == b, isFalse);
    });

    test('equals returns false for different type', () {
      final a = StreamCapsule(
          streamId: 42, type: CapsuleType.registerBidirectionalStream);
      final b = StreamCapsule(
          streamId: 42, type: CapsuleType.registerUnidirectionalStream);
      expect(a == b, isFalse);
    });

    test('equals returns true for identical instance', () {
      final capsule = StreamCapsule(
          streamId: 42, type: CapsuleType.registerBidirectionalStream);
      expect(capsule == capsule, isTrue);
    });

    test('serialize/parse with large streamId', () {
      final original = StreamCapsule(
        streamId: 1000,
        type: CapsuleType.registerBidirectionalStream,
      );
      final bytes = original.serialize();
      // Type (0x41 = 65, which is a 2-byte varint) + streamId (1000 = 2 bytes) = 4 bytes total.
      expect(bytes.length, equals(4));
      final parsed = StreamCapsule.parse(bytes);
      expect(parsed, equals(original));
    });

    test('serialize/parse with multi-byte type', () {
      final original = StreamCapsule(
        streamId: 42,
        type: CapsuleType
            .closeWebTransportSession, // value 0x2843 = 10307 (2-byte varint)
      );
      final bytes = original.serialize();
      // Type (10307 = 2 bytes) + streamId (42 = 1 byte) = 3 bytes total.
      expect(bytes.length, equals(3));
      final parsed = StreamCapsule.parse(bytes);
      expect(parsed, equals(original));
    });
  });

  group('StreamCapsuleRegistry', () {
    test('register and get', () {
      final registry = StreamCapsuleRegistry();
      final capsule = Capsule(
          type: CapsuleType.registerBidirectionalStream, payload: Uint8List(0));
      registry.register(8, capsule);
      expect(registry.get(8), isNotNull);
      expect(registry.get(8)!.streamId, equals(8));
    });

    test('get returns null for unregistered stream', () {
      final registry = StreamCapsuleRegistry();
      expect(registry.get(99), isNull);
    });

    test('isRegistered returns correct boolean', () {
      final registry = StreamCapsuleRegistry();
      final capsule = Capsule(
          type: CapsuleType.registerUnidirectionalStream,
          payload: Uint8List(0));
      registry.register(12, capsule);
      expect(registry.isRegistered(12), isTrue);
      expect(registry.isRegistered(99), isFalse);
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

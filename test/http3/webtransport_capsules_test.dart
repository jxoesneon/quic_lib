import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/http3/capsule_protocol.dart';
import 'package:quic_lib/src/wire/varint.dart';

void main() {
  group('WebTransport flow control capsules', () {
    test('WT_MAX_STREAMS bidi parse and serialize round-trip', () {
      final max = VarInt.encode(42);
      final capsule = WtMaxStreamsCapsule.bidi(Uint8List.fromList(max));
      expect(capsule.type, 0x190B4D3F);
      expect(capsule.maxStreams, 42);

      final serialized = capsule.serialize();
      final (parsed, _) = Capsule.parse(serialized);
      expect(parsed, isA<WtMaxStreamsCapsule>());
      expect((parsed as WtMaxStreamsCapsule).maxStreams, 42);
      expect(parsed.bidirectional, isTrue);
    });

    test('WT_MAX_STREAMS uni parse and serialize round-trip', () {
      final max = VarInt.encode(99);
      final capsule = WtMaxStreamsCapsule.uni(Uint8List.fromList(max));
      expect(capsule.type, 0x190B4D40);
      expect(capsule.maxStreams, 99);
      expect(capsule.bidirectional, isFalse);
    });

    test('WT_MAX_DATA parse and serialize round-trip', () {
      final max = VarInt.encode(12345);
      final capsule = WtMaxDataCapsule(Uint8List.fromList(max));
      expect(capsule.type, 0x190B4D41);
      expect(capsule.maxData, 12345);

      final serialized = capsule.serialize();
      final (parsed, _) = Capsule.parse(serialized);
      expect(parsed, isA<WtMaxDataCapsule>());
      expect((parsed as WtMaxDataCapsule).maxData, 12345);
    });

    test('WT_MAX_STREAM_DATA parse and serialize round-trip', () {
      final max = VarInt.encode(67890);
      final capsule = WtMaxStreamDataCapsule(Uint8List.fromList(max));
      expect(capsule.type, 0x190B4D42);
      expect(capsule.maxStreamData, 67890);

      final serialized = capsule.serialize();
      final (parsed, _) = Capsule.parse(serialized);
      expect(parsed, isA<WtMaxStreamDataCapsule>());
      expect((parsed as WtMaxStreamDataCapsule).maxStreamData, 67890);
    });
  });

  group('Unknown capsule handling', () {
    test('unknown capsule type is parsed as UnknownCapsule', () {
      final data = Uint8List.fromList([1, 2, 3]);
      final capsule = UnknownCapsule(0x9999, data);
      final serialized = capsule.serialize();
      final (parsed, _) = Capsule.parse(serialized);
      expect(parsed, isA<UnknownCapsule>());
      expect(parsed.type, 0x9999);
      expect(parsed.data, [1, 2, 3]);
    });
  });
}

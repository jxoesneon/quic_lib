import 'dart:typed_data';

import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('AckFrequencyFrame', () {
    test('serialize and parse round-trip', () {
      final frame = AckFrequencyFrame(
        sequenceNumber: 42,
        requestedAckElicitingThreshold: 10,
        requestedMaxAckDelay: 25,
        reorderingThreshold: 3,
      );
      final bytes = frame.serialize();
      final (parsed, _) = FrameCodec.parse(bytes);

      expect(parsed, isA<AckFrequencyFrame>());
      final af = parsed as AckFrequencyFrame;
      expect(af.sequenceNumber, equals(42));
      expect(af.requestedAckElicitingThreshold, equals(10));
      expect(af.requestedMaxAckDelay, equals(25));
      expect(af.reorderingThreshold, equals(3));
    });

    test('default reorderingThreshold is 1', () {
      final frame = AckFrequencyFrame(
        sequenceNumber: 0,
        requestedAckElicitingThreshold: 1,
        requestedMaxAckDelay: 0,
      );
      final bytes = frame.serialize();
      final (parsed, _) = FrameCodec.parse(bytes);

      final af = parsed as AckFrequencyFrame;
      expect(af.reorderingThreshold, equals(1));
    });

    test('frame type is 0xaf', () {
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 2,
        requestedMaxAckDelay: 3,
      );
      expect(frame.frameType, equals(0xaf));
      expect(frame.isAckEliciting, isTrue);
    });

    test('getByteLength matches serialized length', () {
      final frame = AckFrequencyFrame(
        sequenceNumber: 255,
        requestedAckElicitingThreshold: 100,
        requestedMaxAckDelay: 50,
        reorderingThreshold: 5,
      );
      expect(frame.getByteLength(), equals(frame.serialize().length));
    });
  });
}

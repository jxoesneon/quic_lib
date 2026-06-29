import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/ack_generator.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/transport_error_codes.dart';

void main() {
  group('AckFrequencyPolicy', () {
    test('processes new ACK_FREQUENCY frame', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 10,
        requestedMaxAckDelay: 5000,
        reorderingThreshold: 3,
      );

      expect(policy.processAckFrequencyFrame(frame), isTrue);
      expect(policy.maxAckDelayUs, 5000);
      expect(policy.reorderingThreshold, 3);
      expect(policy.sequenceNumber, 1);
    });

    test('ignores stale ACK_FREQUENCY frame', () {
      final policy = AckFrequencyPolicy();
      final frame1 = AckFrequencyFrame(
        sequenceNumber: 5,
        requestedAckElicitingThreshold: 10,
        requestedMaxAckDelay: 5000,
        reorderingThreshold: 1,
      );
      final frame2 = AckFrequencyFrame(
        sequenceNumber: 3,
        requestedAckElicitingThreshold: 2,
        requestedMaxAckDelay: 1000,
        reorderingThreshold: 0,
      );

      expect(policy.processAckFrequencyFrame(frame1), isTrue);
      expect(policy.processAckFrequencyFrame(frame2), isFalse);
      // Policy should remain from frame1.
      expect(policy.maxAckDelayUs, 5000);
      expect(policy.reorderingThreshold, 1);
    });

    test('shouldAckImmediate returns true when threshold reached', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 3,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 1,
      );
      policy.processAckFrequencyFrame(frame);

      expect(policy.shouldAckImmediately(), isFalse);
      policy.onPacketReceived(1, isAckEliciting: true);
      expect(policy.shouldAckImmediately(), isFalse);
      policy.onPacketReceived(2, isAckEliciting: true);
      expect(policy.shouldAckImmediately(), isFalse);
      policy.onPacketReceived(3, isAckEliciting: true);
      expect(policy.shouldAckImmediately(), isTrue);
    });

    test('default threshold of 1 acks immediately', () {
      final policy = AckFrequencyPolicy();
      expect(policy.shouldAckImmediately(), isTrue);
    });

    test('onAckSent resets counter', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 5,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 1,
      );
      policy.processAckFrequencyFrame(frame);
      for (var i = 0; i < 5; i++) {
        policy.onPacketReceived(i + 1, isAckEliciting: true);
      }
      expect(policy.shouldAckImmediately(), isTrue);
      policy.onAckSent();
      expect(policy.shouldAckImmediately(), isFalse);
    });

    test('reordering threshold 0 does not trigger immediate ACK on gap', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 100,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 0,
      );
      policy.processAckFrequencyFrame(frame);
      policy.onPacketReceived(1, isAckEliciting: true);
      policy.onPacketReceived(0, isAckEliciting: true);
      expect(policy.shouldAckImmediately(), isFalse);
    });

    test('reordering threshold triggers immediate ACK on large gap', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 100,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 3,
      );
      policy.processAckFrequencyFrame(frame);
      policy.onPacketReceived(10, isAckEliciting: true);
      final shouldAck = policy.onPacketReceived(7, isAckEliciting: true);
      expect(shouldAck, isTrue);
    });

    test('rejects negative requestedAckElicitingThreshold', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: -1,
        requestedMaxAckDelay: 25000,
      );
      expect(() => policy.processAckFrequencyFrame(frame),
          throwsA(isA<FrameEncodingError>()));
    });

    test('rejects requestedMaxAckDelay >= 2^14 ms', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 1,
        requestedMaxAckDelay: 16384 * 1000,
      );
      expect(() => policy.processAckFrequencyFrame(frame),
          throwsA(isA<FrameEncodingError>()));
    });

    test('rejects requestedMaxAckDelay below minAckDelayUs', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 1,
        requestedMaxAckDelay: 1000,
      );
      expect(() => policy.processAckFrequencyFrame(frame, minAckDelayUs: 2000),
          throwsA(isA<FrameEncodingError>()));
    });
  });

  group('AckGenerator with AckFrequencyPolicy', () {
    test('onPacketReceived increments ack-eliciting counter', () {
      final gen = AckGenerator();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 2,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 1,
      );
      gen.frequencyPolicy.processAckFrequencyFrame(frame);

      gen.onPacketReceived(1, 1000, isAckEliciting: true);
      expect(gen.frequencyPolicy.shouldAckImmediately(), isFalse);
      gen.onPacketReceived(2, 2000, isAckEliciting: true);
      expect(gen.frequencyPolicy.shouldAckImmediately(), isTrue);
    });

    test('buildAckFrame resets counter', () {
      final gen = AckGenerator();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 5,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 1,
      );
      gen.frequencyPolicy.processAckFrequencyFrame(frame);
      for (var i = 0; i < 5; i++) {
        gen.onPacketReceived(i + 1, 1000 * (i + 1), isAckEliciting: true);
      }
      expect(gen.frequencyPolicy.shouldAckImmediately(), isTrue);

      gen.buildAckFrame();
      expect(gen.frequencyPolicy.shouldAckImmediately(), isFalse);
    });
  });
}

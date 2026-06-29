import 'package:test/test.dart';
import 'package:quic_lib/src/recovery/ack_generator.dart';
import 'package:quic_lib/src/wire/frame.dart';

void main() {
  group('AckFrequencyPolicy', () {
    test('processes new ACK_FREQUENCY frame', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 10,
        requestedMaxAckDelay: 5000,
        ignoreOrder: true,
      );

      expect(policy.processAckFrequencyFrame(frame), isTrue);
      expect(policy.maxAckDelayUs, 5000);
      expect(policy.ignoreOrder, isTrue);
      expect(policy.sequenceNumber, 1);
    });

    test('ignores stale ACK_FREQUENCY frame', () {
      final policy = AckFrequencyPolicy();
      final frame1 = AckFrequencyFrame(
        sequenceNumber: 5,
        requestedAckElicitingThreshold: 10,
        requestedMaxAckDelay: 5000,
        ignoreOrder: false,
      );
      final frame2 = AckFrequencyFrame(
        sequenceNumber: 3,
        requestedAckElicitingThreshold: 2,
        requestedMaxAckDelay: 1000,
        ignoreOrder: true,
      );

      expect(policy.processAckFrequencyFrame(frame1), isTrue);
      expect(policy.processAckFrequencyFrame(frame2), isFalse);
      // Policy should remain from frame1.
      expect(policy.maxAckDelayUs, 5000);
      expect(policy.ignoreOrder, isFalse);
    });

    test('shouldAckImmediate returns true when threshold reached', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 3,
        requestedMaxAckDelay: 25000,
        ignoreOrder: false,
      );
      policy.processAckFrequencyFrame(frame);

      expect(policy.shouldAckImmediately(), isFalse);
      policy.onAckElicitingPacketReceived();
      expect(policy.shouldAckImmediately(), isFalse);
      policy.onAckElicitingPacketReceived();
      expect(policy.shouldAckImmediately(), isFalse);
      policy.onAckElicitingPacketReceived();
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
        ignoreOrder: false,
      );
      policy.processAckFrequencyFrame(frame);
      for (var i = 0; i < 5; i++) {
        policy.onAckElicitingPacketReceived();
      }
      expect(policy.shouldAckImmediately(), isTrue);
      policy.onAckSent();
      expect(policy.shouldAckImmediately(), isFalse);
    });
  });

  group('AckGenerator with AckFrequencyPolicy', () {
    test('onPacketReceived increments ack-eliciting counter', () {
      final gen = AckGenerator();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 2,
        requestedMaxAckDelay: 25000,
        ignoreOrder: false,
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
        ignoreOrder: false,
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

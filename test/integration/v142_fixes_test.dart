import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/http3/capsule_protocol.dart';
import 'package:quic_lib/src/http3/settings_frame.dart';
import 'package:quic_lib/src/recovery/ack_generator.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/transport_error_codes.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Integration tests for the v1.4.2 RFC compliance and security fixes.
void main() {
  group('RFC 9000 unknown frame handling', () {
    test('FrameCodec.parse throws FrameEncodingError for unknown frame types',
        () {
      final bytes = Uint8List.fromList([0x1f]);
      expect(() => FrameCodec.parse(bytes), throwsA(isA<FrameEncodingError>()));
    });
  });

  group('WebTransport SETTINGS identifiers', () {
    test('WebTransport settings use draft-15 codepoints', () {
      expect(Http3SettingsId.wtEnabled.value, 0x2c7cf000);
      expect(Http3SettingsId.wtInitialMaxData.value, 0x2b61);
      expect(Http3SettingsId.wtInitialMaxStreamsUni.value, 0x2b64);
      expect(Http3SettingsId.wtInitialMaxStreamsBidi.value, 0x2b65);
    });

    test('WebTransport settings round-trip in Http3SettingsFrame', () {
      final frame = Http3SettingsFrame.from(
        wtEnabled: 1,
        wtInitialMaxData: 65536,
        wtInitialMaxStreamsUni: 50,
        wtInitialMaxStreamsBidi: 25,
      );
      final parsed = Http3SettingsFrame.parsePayload(frame.serializePayload());
      expect(parsed.settings[0x2c7cf000], 1);
      expect(parsed.settings[0x2b61], 65536);
      expect(parsed.settings[0x2b64], 50);
      expect(parsed.settings[0x2b65], 25);
    });
  });

  group('RFC 9298 ACK_FREQUENCY frame', () {
    test('AckFrequencyFrame uses Reordering Threshold varint', () {
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 5,
        requestedMaxAckDelay: 10000,
        reorderingThreshold: 3,
      );
      final bytes = frame.serialize();
      final (parsed, _) = FrameCodec.parse(bytes);
      expect(parsed, isA<AckFrequencyFrame>());
      final af = parsed as AckFrequencyFrame;
      expect(af.reorderingThreshold, 3);
      expect(af.getByteLength(), bytes.length);
    });

    test('AckFrequencyPolicy validates ACK_FREQUENCY parameters', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 5,
        requestedMaxAckDelay: 16384 * 1000, // exceeds 2^14 ms limit
      );
      expect(() => policy.processAckFrequencyFrame(frame),
          throwsA(isA<FrameEncodingError>()));
    });

    test('AckFrequencyPolicy triggers immediate ACK on reordering threshold', () {
      final policy = AckFrequencyPolicy();
      final frame = AckFrequencyFrame(
        sequenceNumber: 1,
        requestedAckElicitingThreshold: 100,
        requestedMaxAckDelay: 25000,
        reorderingThreshold: 2,
      );
      policy.processAckFrequencyFrame(frame);
      policy.onPacketReceived(10, isAckEliciting: true);
      expect(policy.onPacketReceived(8, isAckEliciting: true), isTrue);
    });
  });



  group('RFC 9001 key update tracking', () {
    test('KeyManager requires ACK before subsequent key update', () {
      final km = KeyManager.forTest();
      km.onPacketSentWithCurrentKey(1);
      // Without an ACK, a subsequent key update is not allowed.
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));
      km.onAckReceived(1);
      expect(() => km.initiateKeyUpdate(), returnsNormally);
    });

    test('QuicConnection wires KeyManager for application-space packets only', () {
      final km = KeyManager.forTest();
      final conn = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        streamIdAllocator: StreamIdAllocator(),
        keyManager: km,
      );

      // Application-space packet sent must be tracked.
      conn.onPacketSent(
        5,
        DateTime.now().millisecondsSinceEpoch * 1000,
        ackEliciting: true,
        sizeInBytes: 1200,
        spaceIndex: PacketNumberSpace.application.spaceIndex,
      );
      // No ACK yet, so key update should still be disallowed.
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));

      // ACK in non-application space must NOT satisfy the requirement.
      conn.onAckReceived(
        PacketNumberSpace.initial.spaceIndex,
        5,
        [(gap: 0, length: 1)],
      );
      expect(() => km.initiateKeyUpdate(), throwsA(isA<StateError>()));

      // ACK in application space satisfies the requirement.
      conn.onAckReceived(
        PacketNumberSpace.application.spaceIndex,
        5,
        [(gap: 0, length: 1)],
      );
      expect(() => km.initiateKeyUpdate(), returnsNormally);

      // After a key update, reset internal state and verify non-application
      // packets are not tracked.
      km.confirmKeyUpdate();
      final km2 = KeyManager.forTest();
      final conn2 = QuicConnection(
        stateMachine: ConnectionStateMachine(),
        cidManager: ConnectionIdManager(),
        pnSpaceManager: PacketNumberSpaceManager(),
        rttEstimator: RttEstimator(),
        lossDetector: LossDetector(),
        ptoScheduler: PtoScheduler(RttEstimator()),
        streamIdAllocator: StreamIdAllocator(),
        keyManager: km2,
      );
      conn2.onPacketSent(
        7,
        DateTime.now().millisecondsSinceEpoch * 1000,
        ackEliciting: true,
        sizeInBytes: 1200,
        spaceIndex: PacketNumberSpace.initial.spaceIndex,
      );
      conn2.onAckReceived(
        PacketNumberSpace.initial.spaceIndex,
        7,
        [(gap: 0, length: 1)],
      );
      // Because no application-space packet was tracked, the key update should
      // succeed (not be blocked waiting for an application-space ACK).
      expect(() => km2.initiateKeyUpdate(), returnsNormally);
    });
  });

  group('DATAGRAM frame size limits', () {
    test('DATAGRAM with length rejects oversized payload', () {
      // Type 0x31, length 1 MiB + 1, payload of that size.
      final type = Uint8List.fromList([0x31]);
      final length = VarInt.encode(1024 * 1024 + 1);
      final payload = Uint8List(1024 * 1024 + 1);
      final bytes = Uint8List(type.length + length.length + payload.length);
      bytes.setRange(0, type.length, type);
      bytes.setRange(type.length, type.length + length.length, length);
      bytes.setRange(type.length + length.length, bytes.length, payload);
      expect(() => FrameCodec.parse(bytes), throwsA(isA<ArgumentError>()));
    });
  });

  group('Capsule protocol size limits', () {
    test('Capsule.parse rejects oversized unknown capsules', () {
      // Type 0x3F, length 1 MiB + 1, payload of that size.
      final type = Uint8List.fromList([0x3F]);
      final length = VarInt.encode(1024 * 1024 + 1);
      final payload = Uint8List(1024 * 1024 + 1);
      final bytes = Uint8List(type.length + length.length + payload.length);
      bytes.setRange(0, type.length, type);
      bytes.setRange(type.length, type.length + length.length, length);
      bytes.setRange(type.length + length.length, bytes.length, payload);
      expect(() => Capsule.parse(bytes), throwsA(isA<ArgumentError>()));
    });

    test('Capsule.parse returns UnknownCapsule for small unknown types', () {
      final bytes = Uint8List.fromList([0x3F, 0x00]);
      final (parsed, _) = Capsule.parse(bytes);
      expect(parsed, isA<UnknownCapsule>());
      expect(parsed.type, 0x3F);
    });
  });
}

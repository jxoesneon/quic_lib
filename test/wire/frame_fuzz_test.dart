import 'dart:math' show Random;
import 'dart:typed_data';

import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/transport_error_codes.dart';
import 'package:quic_lib/src/wire/varint.dart';
import 'package:test/test.dart';

/// Fuzz/error-path tests for the QUIC frame parser.
///
/// Verifies that malformed frames, unknown types, and truncated payloads are
/// rejected with [ArgumentError] or [FrameEncodingError], rather than silently
/// returning bogus data or crashing with unexpected errors.
void main() {
  group('FrameCodec.parse malformed input', () {
    test('unknown frame type throws FrameEncodingError', () {
      for (final type in [0x1f, 0x21, 0x50, 0x7f, 0xff]) {
        final bytes = Uint8List.fromList([type]);
        expect(
          () => FrameCodec.parse(bytes),
          throwsA(isA<FrameEncodingError>()),
          reason: 'frame type 0x${type.toRadixString(16)}',
        );
      }
    });

    test('empty payload throws ArgumentError', () {
      expect(() => FrameCodec.parse(Uint8List(0)), throwsArgumentError);
    });

    test('truncated length-prefixed frames throw ArgumentError', () {
      final frames = [
        ResetStreamFrame(streamId: 0, errorCode: 0, finalSize: 0),
        StopSendingFrame(streamId: 0, errorCode: 0),
        CryptoFrame(offset: 0, data: [0x01, 0x02, 0x03]),
        NewTokenFrame(token: [0x01, 0x02, 0x03]),
        NewConnectionIdFrame(
          sequenceNumber: 1,
          retirePriorTo: 0,
          connectionId: [0x01, 0x02, 0x03],
          statelessResetToken: List.generate(16, (_) => 0),
        ),
        ConnectionCloseFrame(
          errorCode: 0,
          offendingFrameType: 0,
          reasonPhrase: 'x',
        ),
        ApplicationCloseFrame(errorCode: 0, reasonPhrase: 'x'),
        DatagramFrame(data: Uint8List.fromList([0x01, 0x02]), hasLength: true),
        AckFrequencyFrame(
          sequenceNumber: 1,
          requestedAckElicitingThreshold: 1,
          requestedMaxAckDelay: 0,
        ),
      ];

      for (final frame in frames) {
        final bytes = frame.serialize();
        if (bytes.length <= 1) continue;
        final truncated =
            Uint8List.fromList(bytes.sublist(0, bytes.length - 1));
        expect(
          () => FrameCodec.parse(truncated),
          throwsArgumentError,
          reason: '${frame.runtimeType} truncated',
        );
      }
    });

    test('truncated STREAM frame throws ArgumentError', () {
      final frame = StreamFrame(
        streamId: 0,
        data: [0x01, 0x02, 0x03],
        offset: 0,
        hasExplicitLength: true,
      );
      final bytes = frame.serialize();
      final truncated = Uint8List.fromList(bytes.sublist(0, bytes.length - 1));
      expect(() => FrameCodec.parse(truncated), throwsArgumentError);
    });

    test('ACK frame with too many ranges is rejected', () {
      final builder = BytesBuilder();
      builder.addByte(0x02); // ACK
      builder.add(VarInt.encode(100)); // largest
      builder.add(VarInt.encode(0)); // delay
      builder.add(VarInt.encode(300)); // range count > 256
      builder.add(VarInt.encode(0)); // first range
      expect(() => FrameCodec.parse(builder.toBytes()), throwsArgumentError);
    });

    test('NEW_CONNECTION_ID with oversized CID throws ArgumentError', () {
      final builder = BytesBuilder();
      builder.addByte(0x18);
      builder.add(VarInt.encode(0)); // seq
      builder.add(VarInt.encode(0)); // retire prior to
      builder.addByte(21); // > 20
      expect(() => FrameCodec.parse(builder.toBytes()), throwsArgumentError);
    });

    test('DATAGRAM length exceeds 1MB cap throws ArgumentError', () {
      final builder = BytesBuilder();
      builder.addByte(0x31);
      builder.add(VarInt.encode(1024 * 1024 + 1));
      expect(() => FrameCodec.parse(builder.toBytes()), throwsArgumentError);
    });

    test('CRYPTO length exceeds 16MB cap throws ArgumentError', () {
      final builder = BytesBuilder();
      builder.addByte(0x06);
      builder.add(VarInt.encode(0)); // offset
      builder.add(VarInt.encode(16 * 1024 * 1024 + 1));
      expect(() => FrameCodec.parse(builder.toBytes()), throwsArgumentError);
    });

    test('random byte streams do not cause unexpected failures', () {
      final random = Random(42);
      for (var i = 0; i < 500; i++) {
        final len = random.nextInt(64) + 1;
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => random.nextInt(256)),
        );
        try {
          final (frame, offset) = FrameCodec.parse(bytes);
          expect(offset, greaterThan(0));
          expect(offset, lessThanOrEqualTo(bytes.length));
          expect(frame, isA<Frame>());
        } on ArgumentError catch (_) {
          // Expected.
        } on FrameEncodingError catch (_) {
          // Expected.
        }
      }
    });
  });

  group('FrameCodec.parseAll error handling', () {
    test('parseAll throws when trailing bytes are unparseable', () {
      final bytes = Uint8List.fromList([0x01, 0xFF]);
      expect(
        () => FrameCodec.parseAll(bytes),
        throwsA(anyOf(isA<ArgumentError>(), isA<FrameEncodingError>())),
      );
    });

    test('parseAll accepts well-formed consecutive frames', () {
      final builder = BytesBuilder();
      builder.add(PingFrame().serialize());
      builder.add(PaddingFrame(length: 3).serialize());
      builder.add(PingFrame().serialize());
      final frames = FrameCodec.parseAll(builder.toBytes());
      expect(frames.length, 3);
      expect(frames.whereType<PingFrame>().length, 2);
      expect(frames.whereType<PaddingFrame>().length, 1);
    });
  });
}

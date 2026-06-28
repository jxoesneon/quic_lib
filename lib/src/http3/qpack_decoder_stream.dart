import 'dart:typed_data';

import 'qpack_integer.dart';

/// QPACK decoder stream instructions per RFC 9204 Section 4.3.2.
///
/// These instructions are sent on the decoder stream (0x03) to acknowledge
/// header blocks and update the encoder's insert count.
abstract class DecoderInstruction {
  const DecoderInstruction();

  /// Encode this instruction into a byte sequence.
  Uint8List serialize();

  /// Parse a decoder instruction from [bytes].
  ///
  /// Reads the first byte to determine the instruction type, then decodes
  /// the remaining QPACK integer.
  factory DecoderInstruction.parse(Uint8List bytes) {
    if (bytes.isEmpty) {
      throw ArgumentError('Empty byte buffer');
    }

    final firstByte = bytes[0];

    // Section Acknowledgment: T = 1, 7-bit prefix
    if ((firstByte & 0x80) != 0) {
      final (streamId, _) = QpackInteger.decode(bytes, 0, 7);
      return SectionAcknowledgment(streamId: streamId);
    }

    // Stream Cancellation: T = 01, 6-bit prefix
    if ((firstByte & 0x40) != 0) {
      final (streamId, _) = QpackInteger.decode(bytes, 0, 6);
      return StreamCancellation(streamId: streamId);
    }

    // Insert Count Increment: T = 00, 6-bit prefix
    final (increment, _) = QpackInteger.decode(bytes, 0, 6);
    return InsertCountIncrement(increment: increment);
  }
}

/// Section Acknowledgment instruction (T = 1, 7-bit prefix).
///
/// Sent to acknowledge that a header block for [streamId] has been processed.
class SectionAcknowledgment extends DecoderInstruction {
  final int streamId;

  const SectionAcknowledgment({required this.streamId});

  @override
  Uint8List serialize() {
    final encoded = QpackInteger.encode(streamId, 7);
    encoded[0] |= 0x80; // Set first bit to 1
    return encoded;
  }

  @override
  String toString() => 'SectionAcknowledgment(streamId: $streamId)';
}

/// Stream Cancellation instruction (T = 01, 6-bit prefix).
///
/// Sent to indicate that [streamId] was cancelled before its header block
/// was fully processed.
class StreamCancellation extends DecoderInstruction {
  final int streamId;

  const StreamCancellation({required this.streamId});

  @override
  Uint8List serialize() {
    final encoded = QpackInteger.encode(streamId, 6);
    encoded[0] |= 0x40; // Set first bits to 01
    return encoded;
  }

  @override
  String toString() => 'StreamCancellation(streamId: $streamId)';
}

/// Insert Count Increment instruction (T = 00, 6-bit prefix).
///
/// Sent to inform the encoder that the decoder has received [increment]
/// dynamic table insertions.
class InsertCountIncrement extends DecoderInstruction {
  final int increment;

  const InsertCountIncrement({required this.increment});

  @override
  Uint8List serialize() {
    // T = 00, so the upper two bits are already zero.
    return QpackInteger.encode(increment, 6);
  }

  @override
  String toString() => 'InsertCountIncrement(increment: $increment)';
}

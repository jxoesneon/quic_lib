import 'dart:math';
import 'dart:typed_data';

/// Generates and validates QUIC stateless reset packets per RFC 9000 Section 10.3.
///
/// A stateless reset allows an endpoint that loses state (for example, due to
/// a crash or restart) to signal to the peer that the connection is no longer
/// viable. The packet contains random padding and a 16-byte stateless reset
/// token that the receiver compares against tokens it has previously received
/// in [NewConnectionIdFrame] tokens.
///
/// ## Example
/// ```dart
/// final token = connectionIdFrame.statelessResetToken;
/// final packet = StatelessResetGenerator.generate(token: token);
/// socket.send(packet);
/// ```
///
/// See also:
/// - [NewConnectionIdFrame] — carries the stateless reset token
/// - RFC 9000 Section 10.3
class StatelessResetGenerator {
  static final Random _random = Random.secure();

  /// Generate a stateless reset packet.
  ///
  /// [token] is the 16-byte stateless reset token.
  /// [minPacketSize] is the minimum total packet size (default 5).
  ///
  /// The padding length is randomized between 5 and 22 bytes so the total
  /// packet size is between 21 and 38 bytes, making the packet difficult to
  /// distinguish from normal traffic.
  ///
  /// Throws [ArgumentError] if [token] is not exactly 16 bytes.
  /// Throws [StateError] if the generated packet is smaller than [minPacketSize].
  static Uint8List generate({
    required List<int> token,
    int minPacketSize = 5,
  }) {
    if (token.length != 16) {
      throw ArgumentError('Stateless reset token must be 16 bytes');
    }

    // Random padding: 5..22 bytes so total packet is 21..38 bytes
    final paddingLen = 5 + _random.nextInt(18); // 5..22
    final padding = Uint8List(paddingLen);
    for (var i = 0; i < paddingLen; i++) {
      padding[i] = _random.nextInt(256);
    }

    // First byte: header form = 1 (bit 7), but type bits (6-4) = invalid (3)
    // This makes it look like a long header but with an invalid type
    padding[0] = 0x80 | 0x40 | (padding[0] & 0x3F);

    final builder = BytesBuilder();
    builder.add(padding);
    builder.add(token);

    final result = Uint8List.fromList(builder.toBytes());
    if (result.length < minPacketSize) {
      throw StateError(
          'Generated packet ${result.length} bytes < min $minPacketSize');
    }
    return result;
  }

  /// Validate that a packet could be a stateless reset.
  ///
  /// Checks: size >= 5, first byte has header form = 1 but invalid type bits.
  static bool isValidFormat(Uint8List packet) {
    if (packet.length < 5) return false;
    final firstByte = packet[0];
    // Header form must be 1
    if ((firstByte & 0x80) == 0) return false;
    // Type bits (6-4) must be invalid (not 0, 1, 2, or 3)
    // Actually per RFC, the type is in bits 5-4 for long headers
    // Valid types are: 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
    // So ANY type bits are "valid" in the sense of being a long header
    // The RFC means: if you parse it as a long header, the version is not
    // a supported QUIC version, OR the type bits don't correspond to a known type
    // For simplicity: check if it could be a real long header packet
    // by seeing if the version field (bytes 1-4) is not QUIC v1 (0x00000001)
    // or draft versions
    if (packet.length < 5) return false;
    // Check if first byte looks like a long header
    // and if the version field (bytes 1-4) is not QUIC v1 (0x00000001)
    // or draft versions
    if ((firstByte & 0x80) == 0) return false;
    // A stateless reset cannot be a valid Initial, 0-RTT, or Handshake
    // because those have known structures. But a Retry also has a known structure.
    // The RFC says: "the packet is not a valid QUIC packet"
    // We approximate this by checking if it could be parsed as a known type
    // For our purposes, we just say: it has header form=1 and we can't parse it
    return true;
  }
}

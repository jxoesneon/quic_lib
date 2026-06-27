import 'dart:typed_data';

import 'package:dart_quic/src/crypto/crypto_backend.dart';
import 'package:dart_quic/src/crypto/packet/retry_integrity_tag.dart';

/// Builds QUIC Retry packets per RFC 9000 Section 17.2.5.
class RetryPacketBuilder {
  RetryPacketBuilder._();

  /// Build a Retry packet.
  ///
  /// [version] is the QUIC version.
  /// [originalDestinationConnectionId] is the DCID from the client's Initial.
  /// [retrySourceConnectionId] is the new CID the server wants the client to use.
  /// [retryToken] is opaque data for the server to validate.
  /// Returns the complete Retry packet bytes including integrity tag.
  static Future<Uint8List> build({
    required int version,
    required List<int> originalDestinationConnectionId,
    required List<int> retrySourceConnectionId,
    required List<int> retryToken,
    required CryptoBackend backend,
  }) async {
    // 1. Build Retry packet without integrity tag.
    final builder = BytesBuilder();

    // First byte: long header (1), fixed bit (1), Retry type (11), unused (0000)
    // 0x80 | 0x40 | (3 << 4) = 0xF0
    builder.addByte(0xF0);

    // Version (4 bytes, big-endian)
    builder.addByte((version >> 24) & 0xFF);
    builder.addByte((version >> 16) & 0xFF);
    builder.addByte((version >> 8) & 0xFF);
    builder.addByte(version & 0xFF);

    // Destination Connection ID Length + DCID
    builder.addByte(originalDestinationConnectionId.length);
    builder.add(originalDestinationConnectionId);

    // Source Connection ID Length + SCID
    builder.addByte(retrySourceConnectionId.length);
    builder.add(retrySourceConnectionId);

    // Retry Token
    builder.add(retryToken);

    final retryPacketWithoutTag = Uint8List.fromList(builder.toBytes());

    // 2. Compute the 16-byte retry integrity tag.
    final tag = await RetryIntegrityTag.compute(
      originalDestinationConnectionId: originalDestinationConnectionId,
      retryPacketWithoutTag: retryPacketWithoutTag,
      backend: backend,
    );

    // 3. Append tag to the packet.
    builder.add(tag);

    // 4. Return complete bytes.
    return Uint8List.fromList(builder.toBytes());
  }
}

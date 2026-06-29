import 'dart:typed_data';

import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Full QUIC header protection + AEAD round-trip codec.
///
/// Encapsulates the packet protection pipeline:
///   plaintext packet → split header/payload → AEAD encrypt → apply header mask
///   protected packet → remove header mask → AEAD decrypt → parse frames
class ProtectedPacketCodec {
  final PacketNumberSpaceKeys keys;
  final int destinationConnectionIdLength;

  ProtectedPacketCodec({
    required this.keys,
    this.destinationConnectionIdLength = 8,
  });

  /// Encrypts the payload of [plaintextPacket] and applies header protection.
  ///
  /// [packetNumber] is the full packet number used for nonce construction.
  ///
  /// The caller is responsible for ensuring that long-header packets have
  /// the correct `Length` field (covering PN + ciphertext including tag).
  Future<Uint8List> protectAndEncrypt(
    Uint8List plaintextPacket,
    int packetNumber,
  ) async {
    final isLong = (plaintextPacket[0] & 0x80) != 0;
    final (header, payload) = _splitPlaintext(plaintextPacket, isLong);

    final ciphertext = await keys.encrypt(packetNumber, header, payload);
    final protectedHeader = keys.protectHeader(header, ciphertext);

    final result = Uint8List(protectedHeader.length + ciphertext.length);
    result.setRange(0, protectedHeader.length, protectedHeader);
    result.setRange(protectedHeader.length, result.length, ciphertext);
    return result;
  }

  /// Removes header protection from [protectedPacket], decrypts the payload,
  /// and parses the resulting frames.
  ///
  /// Returns the unprotected header bytes, the list of parsed frames, and the
  /// key phase bit for short-header packets (null for long headers), or `null`
  /// if the packet could not be successfully unprotected.
  ///
  /// Throws if header protection is successfully removed but AEAD decryption
  /// fails (e.g., corrupted ciphertext or authentication tag).

  /// Remove header protection from [protectedPacket] and return the
  /// unprotected header bytes, or null if header protection cannot be removed.
  ///
  /// For short headers, [pnLen] is the packet-number length in bytes (1-4).
  /// The caller should determine the correct [pnLen] by trying all four values
  /// or by using packet-number reconstruction.
  Uint8List? unprotectHeader(Uint8List protectedPacket, int pnLen) {
    if (protectedPacket.isEmpty) return null;
    final isLong = (protectedPacket[0] & 0x80) != 0;
    if (isLong) {
      return _unprotectLongHeader(protectedPacket, pnLen);
    } else {
      return _unprotectShortHeader(protectedPacket, pnLen);
    }
  }

  Uint8List? _unprotectLongHeader(Uint8List protectedPacket, int pnLen) {
    final pnOffset = _computeLongHeaderPnOffset(protectedPacket);
    final headerLen = pnOffset + pnLen;
    if (headerLen > protectedPacket.length) return null;
    final header = protectedPacket.sublist(0, headerLen);
    final payload = protectedPacket.sublist(headerLen);
    try {
      return keys.unprotectHeader(header, payload);
    } catch (_) {
      return null;
    }
  }

  Uint8List? _unprotectShortHeader(Uint8List protectedPacket, int pnLen) {
    final headerLen = 1 + destinationConnectionIdLength + pnLen;
    if (headerLen > protectedPacket.length) return null;
    final header = protectedPacket.sublist(0, headerLen);
    final payload = protectedPacket.sublist(headerLen);
    try {
      return keys.headerProtection.removeShortHeader(header, payload, pnLen);
    } catch (_) {
      return null;
    }
  }

  /// Decrypt the [payload] of a packet given the [unprotectedHeader] and full
  /// [packetNumber]. Returns the parsed frames, or null if decryption fails.
  Future<List<Frame>?> decryptPayload(
    Uint8List unprotectedHeader,
    Uint8List payload,
    int packetNumber,
  ) async {
    try {
      final plaintext =
          await keys.decrypt(packetNumber, unprotectedHeader, payload);
      return _parseFrames(plaintext);
    } catch (_) {
      return null;
    }
  }

  Future<({Uint8List header, List<Frame> frames, int? keyPhase})?>
      unprotectAndDecrypt(
    Uint8List protectedPacket,
  ) async {
    if (protectedPacket.isEmpty) return null;

    final isLong = (protectedPacket[0] & 0x80) != 0;
    if (isLong) {
      return _unprotectAndDecryptLongHeader(protectedPacket);
    } else {
      return _unprotectAndDecryptShortHeader(protectedPacket);
    }
  }

  (Uint8List header, Uint8List payload) _splitPlaintext(
    Uint8List packet,
    bool isLong,
  ) {
    if (isLong) {
      final pnLen = (packet[0] & 0x03) + 1;
      final pnOffset = _computeLongHeaderPnOffset(packet);
      final headerLen = pnOffset + pnLen;
      return (packet.sublist(0, headerLen), packet.sublist(headerLen));
    } else {
      final pnLen = (packet[0] & 0x03) + 1;
      final headerLen = 1 + destinationConnectionIdLength + pnLen;
      return (packet.sublist(0, headerLen), packet.sublist(headerLen));
    }
  }

  Future<({Uint8List header, List<Frame> frames, int? keyPhase})?>
      _unprotectAndDecryptLongHeader(Uint8List packet) async {
    final pnOffset = _computeLongHeaderPnOffset(packet);

    for (var pnLen = 1; pnLen <= 4; pnLen++) {
      final headerLen = pnOffset + pnLen;
      if (headerLen > packet.length) continue;

      final header = packet.sublist(0, headerLen);
      final payload = packet.sublist(headerLen);

      Uint8List unprotectedHeader;
      try {
        unprotectedHeader = keys.unprotectHeader(header, payload);
      } catch (_) {
        continue;
      }

      final actualPnLen = (unprotectedHeader[0] & 0x03) + 1;
      if (actualPnLen != pnLen) continue;

      final packetNumber = _decodePacketNumber(
        unprotectedHeader.sublist(pnOffset, pnOffset + pnLen),
      );

      final plaintext =
          await keys.decrypt(packetNumber, unprotectedHeader, payload);
      final frames = _parseFrames(plaintext);
      return (header: unprotectedHeader, frames: frames, keyPhase: null);
    }

    return null;
  }

  Future<({Uint8List header, List<Frame> frames, int? keyPhase})?>
      _unprotectAndDecryptShortHeader(Uint8List packet) async {
    for (var pnLen = 1; pnLen <= 4; pnLen++) {
      final headerLen = 1 + destinationConnectionIdLength + pnLen;
      if (headerLen > packet.length) continue;

      final header = packet.sublist(0, headerLen);
      final payload = packet.sublist(headerLen);

      Uint8List unprotectedHeader;
      try {
        unprotectedHeader =
            keys.headerProtection.removeShortHeader(header, payload, pnLen);
      } catch (_) {
        continue;
      }

      final actualPnLen = (unprotectedHeader[0] & 0x03) + 1;
      if (actualPnLen != pnLen) continue;

      final packetNumber = _decodePacketNumber(
        unprotectedHeader.sublist(
          1 + destinationConnectionIdLength,
          1 + destinationConnectionIdLength + pnLen,
        ),
      );

      try {
        final plaintext =
            await keys.decrypt(packetNumber, unprotectedHeader, payload);
        final frames = _parseFrames(plaintext);
        final keyPhase = (unprotectedHeader[0] & 0x04) != 0 ? 1 : 0;
        return (header: unprotectedHeader, frames: frames, keyPhase: keyPhase);
      } catch (_) {
        // Decrypt failed (likely wrong pnLen guess); try next pnLen.
        continue;
      }
    }

    return null;
  }

  static int _decodePacketNumber(Uint8List bytes) {
    var result = 0;
    for (final b in bytes) {
      result = (result << 8) | b;
    }
    return result;
  }

  static List<Frame> _parseFrames(Uint8List bytes) {
    final frames = <Frame>[];
    var offset = 0;
    while (offset < bytes.length) {
      final (frame, newOffset) = FrameCodec.parse(bytes, offset: offset);
      frames.add(frame);
      offset = newOffset;
    }
    return frames;
  }

  /// Computes the offset of the packet number field for a long header.
  /// Mirrors the logic in [HeaderProtection._computeLongHeaderPnOffset].
  static int _computeLongHeaderPnOffset(Uint8List header) {
    var offset = 1; // skip first byte

    // Version (4 bytes)
    offset += 4;
    if (header.length < offset + 1) {
      throw ArgumentError('Header too short for DCID length');
    }
    final dcidLen = header[offset];
    offset += 1 + dcidLen;

    if (header.length < offset + 1) {
      throw ArgumentError('Header too short for SCID length');
    }
    final scidLen = header[offset];
    offset += 1 + scidLen;

    // Packet type is in bits 4-5 of the first byte
    final packetType = (header[0] >> 4) & 0x03;
    if (packetType == 0) {
      // Initial: token length varint
      if (header.length < offset + 1) {
        throw ArgumentError('Header too short for token length');
      }
      final tokenLen = _readVarInt(header, offset);
      final tokenLenBytes = _varIntLength(header[offset]);
      offset += tokenLenBytes + tokenLen;
    }

    if (header.length < offset + 1) {
      throw ArgumentError('Header too short for length field');
    }
    final lengthBytes = _varIntLength(header[offset]);
    offset += lengthBytes;

    if (offset > header.length) {
      throw ArgumentError('Header too short for length field bytes');
    }

    return offset;
  }

  static int _readVarInt(Uint8List bytes, int offset) {
    if (offset >= bytes.length) return 0;
    final firstByte = bytes[offset];
    final length = 1 << (firstByte >> 6);
    if (offset + length > bytes.length) return 0;
    var value = firstByte & 0x3F;
    for (var i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  static int _varIntLength(int firstByte) => 1 << (firstByte >> 6);

  /// Patch the `Length` field in a plaintext long-header packet to account
  /// for the AEAD [tagLength].
  ///
  /// Returns a new packet with the updated `Length` varint. Short-header
  /// packets are returned unchanged.
  static Uint8List patchLongHeaderLength(Uint8List plaintext, int tagLength) {
    if ((plaintext[0] & 0x80) == 0) return plaintext;

    // Find the Length field offset by mirroring _computeLongHeaderPnOffset.
    var offset = 1 + 4;
    final dcidLen = plaintext[offset];
    offset += 1 + dcidLen;
    final scidLen = plaintext[offset];
    offset += 1 + scidLen;
    final packetType = (plaintext[0] >> 4) & 0x03;
    if (packetType == 0x00) {
      final tokenLen = _readVarInt(plaintext, offset);
      final tokenLenBytes = _varIntLength(plaintext[offset]);
      offset += tokenLenBytes + tokenLen;
    }

    final lengthOffset = offset;
    final oldLengthBytes = _varIntLength(plaintext[offset]);
    final oldLength = _readVarInt(plaintext, offset);
    final newLength = oldLength + tagLength;
    final newLengthBytes = VarInt.encode(newLength);

    if (newLengthBytes.length == oldLengthBytes) {
      final result = Uint8List.fromList(plaintext);
      for (var i = 0; i < newLengthBytes.length; i++) {
        result[lengthOffset + i] = newLengthBytes[i];
      }
      return result;
    }

    final builder = BytesBuilder();
    builder.add(plaintext.sublist(0, lengthOffset));
    builder.add(newLengthBytes);
    builder.add(plaintext.sublist(lengthOffset + oldLengthBytes));
    return Uint8List.fromList(builder.toBytes());
  }
}

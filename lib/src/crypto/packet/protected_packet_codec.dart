import 'dart:typed_data';

import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/wire/frame.dart';

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
  /// Returns the unprotected header bytes and the list of parsed frames,
  /// or `null` if the packet could not be successfully unprotected.
  ///
  /// Throws if header protection is successfully removed but AEAD decryption
  /// fails (e.g., corrupted ciphertext or authentication tag).
  Future<({Uint8List header, List<Frame> frames})?> unprotectAndDecrypt(
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

  Future<({Uint8List header, List<Frame> frames})?>
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
      return (header: unprotectedHeader, frames: frames);
    }

    return null;
  }

  Future<({Uint8List header, List<Frame> frames})?>
      _unprotectAndDecryptShortHeader(Uint8List packet) async {
    for (var pnLen = 1; pnLen <= 4; pnLen++) {
      final headerLen = 1 + destinationConnectionIdLength + pnLen;
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
        unprotectedHeader.sublist(
          1 + destinationConnectionIdLength,
          1 + destinationConnectionIdLength + pnLen,
        ),
      );

      final plaintext =
          await keys.decrypt(packetNumber, unprotectedHeader, payload);
      final frames = _parseFrames(plaintext);
      return (header: unprotectedHeader, frames: frames);
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
}

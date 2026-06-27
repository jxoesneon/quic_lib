import 'dart:typed_data';

import 'package:cryptography/dart.dart' as dart_crypto;
import 'package:pointycastle/export.dart' as pc;

/// QUIC header protection per RFC 9001 Section 5.4.
class HeaderProtection {
  final List<int> _hpKey;
  final bool _isChaCha20;

  HeaderProtection({
    required List<int> hpKey,
    required bool isChaCha20,
  })  : _hpKey = hpKey,
        _isChaCha20 = isChaCha20;

  /// Apply header protection to a packet.
  /// [header] is the unprotected header bytes.
  /// [payload] is the encrypted payload (needed for sample extraction).
  /// Returns the protected header bytes.
  Uint8List apply(Uint8List header, Uint8List payload) {
    final isLong = (header[0] & 0x80) != 0;
    final pnLen = (header[0] & 0x03) + 1;
    final pnOffset = header.length - pnLen;
    return _applyMask(header, payload, pnOffset, pnLen, isLong);
  }

  /// Remove header protection from a packet.
  /// [header] is the protected header bytes.
  /// [payload] is the encrypted payload.
  /// Returns the unprotected header bytes.
  Uint8List remove(Uint8List header, Uint8List payload) {
    final isLong = (header[0] & 0x80) != 0;
    if (isLong) {
      final pnOffset = _computeLongHeaderPnOffset(header);
      final pnLen = header.length - pnOffset;
      if (pnLen < 1 || pnLen > 4) {
        throw ArgumentError('Invalid packet number length: $pnLen');
      }
      return _applyMask(header, payload, pnOffset, pnLen, isLong);
    }

    // Short header: packet-number length is masked in the first byte,
    // so we try all four possibilities and verify by re-applying.
    Uint8List? bestCandidate;
    for (var pnLen = 1; pnLen <= 4; pnLen++) {
      final pnOffset = header.length - pnLen;
      final sampleStart = 4 - pnLen;
      if (sampleStart < 0 || sampleStart + 16 > payload.length) {
        continue;
      }
      final candidate = _applyMask(header, payload, pnOffset, pnLen, isLong);
      // Verify round-trip.
      final reprotected = apply(candidate, payload);
      if (_listEquals(reprotected, header)) {
        bestCandidate = candidate;
        // Prefer the smallest valid pnLen in the astronomically unlikely
        // case of multiple matches.
        break;
      }
    }

    if (bestCandidate == null) {
      throw StateError('Unable to remove short header protection');
    }
    return bestCandidate;
  }

  Uint8List _applyMask(
    Uint8List header,
    Uint8List payload,
    int pnOffset,
    int pnLen,
    bool isLong,
  ) {
    final sampleStart = 4 - pnLen;
    if (sampleStart < 0 || sampleStart + 16 > payload.length) {
      throw ArgumentError('Payload too short for header protection sample');
    }
    final sample = payload.sublist(sampleStart, sampleStart + 16);
    final mask = _generateMask(sample);
    final result = Uint8List.fromList(header);

    if (isLong) {
      result[0] ^= mask[0] & 0x0F;
    } else {
      result[0] ^= mask[0] & 0x1F;
    }

    for (var i = 0; i < pnLen; i++) {
      result[pnOffset + i] ^= mask[1 + i];
    }

    return result;
  }

  Uint8List _generateMask(List<int> sample) {
    if (_isChaCha20) {
      final counter = ByteData.view(
        Uint8List.fromList(sample.sublist(0, 4)).buffer,
      ).getUint32(0, Endian.little);
      final nonce = sample.sublist(4, 16);

      final state = Uint32List(16);
      dart_crypto.DartChacha20.initializeChacha(
        state,
        key: _hpKey,
        nonce: nonce,
        keyStreamIndex: counter * 64,
      );

      final keystream = Uint32List(16);
      dart_crypto.DartChacha20.chachaRounds(
        keystream,
        0,
        state,
        rounds: 20,
        addAndXor: true,
      );

      final mask = Uint8List(5);
      final bd = ByteData.view(mask.buffer);
      bd.setUint32(0, keystream[0], Endian.little);
      mask[4] = keystream[1] & 0xFF;
      return mask;
    }

    // AES-ECB
    final key = Uint8List.fromList(_hpKey);
    final sampleBlock = Uint8List.fromList(sample);
    final aesEngine = pc.AESEngine();
    final ecb = pc.ECBBlockCipher(aesEngine);
    ecb.init(true, pc.KeyParameter(key));
    final output = Uint8List(16);
    ecb.processBlock(sampleBlock, 0, output, 0);
    return output.sublist(0, 5);
  }

  /// Computes the offset of the packet number field for a long header.
  /// The caller must ensure the header is a valid long header.
  int _computeLongHeaderPnOffset(Uint8List header) {
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

    // Packet type is in bits 4-5 of the first byte; mask only affects lower 4 bits.
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
    // SECURITY: Guard against reading past buffer end.
    if (offset >= bytes.length) return 0;
    final firstByte = bytes[offset];
    final length = 1 << (firstByte >> 6);
    // SECURITY: Ensure all continuation bytes are present.
    if (offset + length > bytes.length) return 0;
    var value = firstByte & 0x3F;
    for (var i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return value;
  }

  static int _varIntLength(int firstByte) => 1 << (firstByte >> 6);

  static bool _listEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

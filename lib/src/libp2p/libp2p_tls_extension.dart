import 'dart:typed_data';

// ---------------------------------------------------------------------------
// Minimal protobuf varint encode / decode helpers
// ---------------------------------------------------------------------------

Uint8List _encodeVarint(int value) {
  final bytes = <int>[];
  var v = value;
  while (v > 0x7F) {
    bytes.add((v & 0x7F) | 0x80);
    v >>= 7;
  }
  bytes.add(v & 0x7F);
  return Uint8List.fromList(bytes);
}

int _varintLength(int value) {
  var len = 0;
  var v = value;
  do {
    len++;
    v >>= 7;
  } while (v > 0);
  return len;
}

/// A protobuf-encoded signed key used in the libp2p TLS extension.
///
/// The wire format is:
/// ```
/// message SignedKey {
///   bytes public_key  = 1;
///   bytes signature   = 2;
/// }
/// ```
class SignedKey {
  /// The peer's raw public key bytes.
  final Uint8List publicKey;

  /// Signature of [publicKey] by the host's identity key.
  final Uint8List signature;

  SignedKey({required this.publicKey, required this.signature});

  /// Encodes this [SignedKey] as a protobuf message.
  Uint8List serialize() {
    // field 1, wire type 2 (length-delimited): tag = (1 << 3) | 2 = 10
    // field 2, wire type 2 (length-delimited): tag = (2 << 3) | 2 = 18
    final pkLen = publicKey.length;
    final sigLen = signature.length;
    final totalLen =
        1 + _varintLength(pkLen) + pkLen + 1 + _varintLength(sigLen) + sigLen;
    final result = Uint8List(totalLen);
    var offset = 0;

    result[offset++] = 0x0A; // field 1, type 2
    final pkLenBytes = _encodeVarint(pkLen);
    result.setRange(offset, offset + pkLenBytes.length, pkLenBytes);
    offset += pkLenBytes.length;
    result.setRange(offset, offset + pkLen, publicKey);
    offset += pkLen;

    result[offset++] = 0x12; // field 2, type 2
    final sigLenBytes = _encodeVarint(sigLen);
    result.setRange(offset, offset + sigLenBytes.length, sigLenBytes);
    offset += sigLenBytes.length;
    result.setRange(offset, offset + sigLen, signature);
    offset += sigLen;

    return result;
  }

  /// Decodes a [SignedKey] from protobuf bytes.
  static SignedKey parse(Uint8List bytes) {
    Uint8List? pk;
    Uint8List? sig;
    var offset = 0;

    while (offset < bytes.length) {
      final tag = bytes[offset++];
      final fieldNumber = tag >> 3;
      final wireType = tag & 0x07;

      if (wireType == 2) {
        // length-delimited
        var length = 0;
        var shift = 0;
        while (offset < bytes.length) {
          final b = bytes[offset];
          length |= (b & 0x7F) << shift;
          offset++;
          if ((b & 0x80) == 0) break;
          shift += 7;
        }
        if (offset + length > bytes.length) {
          throw FormatException('Protobuf length exceeds buffer');
        }
        final value = bytes.sublist(offset, offset + length);
        offset += length;
        if (fieldNumber == 1) {
          pk = value;
        } else if (fieldNumber == 2) {
          sig = value;
        }
      } else {
        // Skip unknown wire types
        break;
      }
    }

    if (pk == null || sig == null) {
      throw FormatException('Missing required fields in SignedKey');
    }
    return SignedKey(publicKey: pk, signature: sig);
  }
}

/// The libp2p TLS X.509 certificate extension.
///
/// Per the libp2p TLS specification, this extension carries a [SignedKey]
/// protobuf that binds the TLS certificate to a libp2p peer identity.
///
/// See: https://github.com/libp2p/specs/blob/master/tls/tls.md
class Libp2pExtension {
  /// The OID assigned to the libp2p TLS extension.
  static const String oid = '1.3.6.1.4.1.53594.1.1';

  /// The signed key embedded in this extension.
  final SignedKey signedKey;

  Libp2pExtension({required this.signedKey});

  /// Returns the protobuf-encoded [SignedKey] bytes.
  Uint8List serialize() => signedKey.serialize();

  /// Parses a [Libp2pExtension] from protobuf-encoded [SignedKey] bytes.
  static Libp2pExtension parse(Uint8List bytes) {
    return Libp2pExtension(signedKey: SignedKey.parse(bytes));
  }
}

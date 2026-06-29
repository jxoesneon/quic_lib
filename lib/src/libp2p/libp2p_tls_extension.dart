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

/// libp2p public key types per the libp2p TLS spec.
///
/// Values match the protobuf enum used in the libp2p PublicKey message.
enum Libp2pKeyType {
  rsa(0),
  ed25519(1),
  secp256k1(2),
  ecdsa(3);

  final int value;
  const Libp2pKeyType(this.value);

  static Libp2pKeyType? fromValue(int value) {
    for (final type in values) {
      if (type.value == value) return type;
    }
    return null;
  }
}

/// A protobuf-encoded libp2p public key used in the libp2p TLS extension.
///
/// Wire format:
/// ```
/// message PublicKey {
///   required KeyType Type = 1;
///   required bytes Data = 2;
/// }
/// ```
class Libp2pPublicKey {
  final Libp2pKeyType type;
  final Uint8List data;

  Libp2pPublicKey({required this.type, required this.data});

  Uint8List serialize() {
    final typeLen = _varintLength(type.value);
    final dataLen = data.length;
    final totalLen = 1 + typeLen + 1 + _varintLength(dataLen) + dataLen;
    final result = Uint8List(totalLen);
    var offset = 0;

    result[offset++] = 0x08; // field 1, type 0 (varint)
    final typeBytes = _encodeVarint(type.value);
    result.setRange(offset, offset + typeBytes.length, typeBytes);
    offset += typeBytes.length;

    result[offset++] = 0x12; // field 2, type 2 (length-delimited)
    final dataLenBytes = _encodeVarint(dataLen);
    result.setRange(offset, offset + dataLenBytes.length, dataLenBytes);
    offset += dataLenBytes.length;
    result.setRange(offset, offset + dataLen, data);

    return result;
  }

  static Libp2pPublicKey parse(Uint8List bytes) {
    Libp2pKeyType? type;
    Uint8List? data;
    var offset = 0;

    while (offset < bytes.length) {
      final tag = bytes[offset++];
      final fieldNumber = tag >> 3;
      final wireType = tag & 0x07;

      if (fieldNumber == 1 && wireType == 0) {
        var value = 0;
        var shift = 0;
        while (offset < bytes.length) {
          final b = bytes[offset];
          value |= (b & 0x7F) << shift;
          offset++;
          if ((b & 0x80) == 0) break;
          shift += 7;
        }
        type = Libp2pKeyType.fromValue(value);
      } else if (fieldNumber == 2 && wireType == 2) {
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
        data = bytes.sublist(offset, offset + length);
        offset += length;
      } else {
        break;
      }
    }

    if (type == null || data == null) {
      throw FormatException('Missing required fields in PublicKey');
    }
    return Libp2pPublicKey(type: type, data: data);
  }
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
///
/// The [publicKey] field contains a serialized [Libp2pPublicKey] protobuf. The
/// [signature] is computed over the UTF-8 string `libp2p-tls-handshake:`
/// concatenated with the SubjectPublicKeyInfo DER of the certificate carrying
/// the extension.
class SignedKey {
  /// The peer's protobuf-encoded public key.
  final Libp2pPublicKey publicKey;

  /// Signature of the libp2p TLS handshake message by the host identity key.
  final Uint8List signature;

  SignedKey({required this.publicKey, required this.signature});

  /// Encodes this [SignedKey] as a protobuf message.
  Uint8List serialize() {
    final pkBytes = publicKey.serialize();
    final pkLen = pkBytes.length;
    final sigLen = signature.length;
    final totalLen =
        1 + _varintLength(pkLen) + pkLen + 1 + _varintLength(sigLen) + sigLen;
    final result = Uint8List(totalLen);
    var offset = 0;

    result[offset++] = 0x0A; // field 1, type 2
    final pkLenBytes = _encodeVarint(pkLen);
    result.setRange(offset, offset + pkLenBytes.length, pkLenBytes);
    offset += pkLenBytes.length;
    result.setRange(offset, offset + pkLen, pkBytes);
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
    Uint8List? pkBytes;
    Uint8List? sig;
    var offset = 0;

    while (offset < bytes.length) {
      final tag = bytes[offset++];
      final fieldNumber = tag >> 3;
      final wireType = tag & 0x07;

      if (wireType == 2) {
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
          pkBytes = value;
        } else if (fieldNumber == 2) {
          sig = value;
        }
      } else {
        break;
      }
    }

    if (pkBytes == null || sig == null) {
      throw FormatException('Missing required fields in SignedKey');
    }
    return SignedKey(
      publicKey: Libp2pPublicKey.parse(pkBytes),
      signature: sig,
    );
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

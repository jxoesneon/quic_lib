import 'dart:typed_data';

/// Builds a minimal DER-encoded X.509 certificate structure for testing.
///
/// The structure is syntactically valid but contains no real cryptographic
/// material.  It satisfies the minimum structural requirements of
/// [parseX509] (3 top-level elements in the outer SEQUENCE).
Uint8List buildMinimalCert() {
  final builder = BytesBuilder();

  // TBSCertificate (SEQUENCE)
  final tbs = _buildTbsCertificate();
  // SignatureAlgorithm (SEQUENCE)
  final sigAlg = _buildSignatureAlgorithm();
  // SignatureValue (BIT STRING)
  final sigValue = _buildBitString([]);

  // Outer certificate SEQUENCE
  final certContent = BytesBuilder()
    ..add(tbs)
    ..add(sigAlg)
    ..add(sigValue);

  final certContentBytes = certContent.toBytes();
  builder.addByte(0x30); // SEQUENCE
  builder.add(_encodeLength(certContentBytes.length));
  builder.add(certContentBytes);

  return Uint8List.fromList(builder.toBytes());
}

Uint8List _buildTbsCertificate() {
  final builder = BytesBuilder();

  // SerialNumber (INTEGER) - just 1
  builder.addByte(0x02); // INTEGER
  builder.addByte(0x01); // length 1
  builder.addByte(0x01); // value 1

  // SignatureAlgorithm (SEQUENCE)
  final sigAlg = _buildSignatureAlgorithm();
  builder.add(sigAlg);

  // Issuer — use an INTEGER placeholder so x509_parser skips it as non-SEQUENCE.
  builder.add(_buildInteger(0));

  // Validity (SEQUENCE)
  final validity = _buildValidity();
  builder.add(validity);

  // Subject — use an INTEGER placeholder so x509_parser skips it as non-SEQUENCE.
  builder.add(_buildInteger(0));

  // SubjectPublicKeyInfo (SEQUENCE)
  final spki = _buildEmptySequence();
  builder.add(spki);

  final content = builder.toBytes();
  return Uint8List.fromList([
    0x30, // SEQUENCE
    ..._encodeLength(content.length),
    ...content,
  ]);
}

Uint8List _buildSignatureAlgorithm() {
  // SEQUENCE { OID, NULL }
  // ed25519 OID: 1.3.101.112
  final oid = [0x06, 0x03, 0x2B, 0x65, 0x70]; // OID 1.3.101.112
  final nullParam = [0x05, 0x00]; // NULL
  final content = [...oid, ...nullParam];
  return Uint8List.fromList([
    0x30, // SEQUENCE
    ..._encodeLength(content.length),
    ...content,
  ]);
}

Uint8List _buildEmptySequence() {
  return Uint8List.fromList([0x30, 0x00]);
}

Uint8List _buildInteger(int value) {
  return Uint8List.fromList([0x02, 0x01, value & 0xFF]);
}

Uint8List _buildValidity() {
  final builder = BytesBuilder();
  // notBefore: UTCTime 010101000000Z (2001-01-01)
  final notBefore = _buildUtcTime('010101000000Z');
  builder.add(notBefore);
  // notAfter: UTCTime 300101000000Z (2030-01-01)
  final notAfter = _buildUtcTime('300101000000Z');
  builder.add(notAfter);

  final content = builder.toBytes();
  return Uint8List.fromList([
    0x30, // SEQUENCE
    ..._encodeLength(content.length),
    ...content,
  ]);
}

Uint8List _buildUtcTime(String value) {
  // UTCTime uses 2-digit years (YYMMDDHHMMSSZ).
  // For 2001-01-01 00:00:00Z → '010101000000Z'
  // For 2030-01-01 00:00:00Z → '300101000000Z'
  final bytes = value.codeUnits;
  return Uint8List.fromList([
    0x17, // UTCTime
    bytes.length,
    ...bytes,
  ]);
}

Uint8List _buildBitString(List<int> data) {
  // BIT STRING with 0 unused bits
  final content = [0x00, ...data]; // unused bits prefix
  return Uint8List.fromList([
    0x03, // BIT STRING
    ..._encodeLength(content.length),
    ...content,
  ]);
}

List<int> _encodeLength(int length) {
  if (length < 0x80) {
    return [length];
  } else if (length <= 0xFF) {
    return [0x81, length];
  } else if (length <= 0xFFFF) {
    return [0x82, length >> 8, length & 0xFF];
  } else {
    return [0x83, length >> 16, (length >> 8) & 0xFF, length & 0xFF];
  }
}

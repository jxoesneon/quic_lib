import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';

import '../crypto/crypto_backend.dart';
import '../crypto/tls/certificate_chain.dart';
import 'libp2p_tls_extension.dart';

/// Generates an ephemeral self-signed X.509 certificate with the libp2p
/// TLS extension for use in libp2p QUIC handshakes.
///
/// The generated certificate contains:
/// * An ephemeral ECDSA P-256 key pair.
/// * A self-signature over the TBS certificate.
/// * The libp2p extension (OID `1.3.6.1.4.1.53594.1.1`) embedding a
///   [SignedKey] protobuf signed by the host's long-term identity key.
///
/// Per the libp2p TLS specification, the ephemeral certificate proves that
/// the peer controlling the TLS handshake also controls the libp2p
/// identity referenced by the extension.
class Libp2pCertificateGenerator {
  final CryptoBackend _backend;

  Libp2pCertificateGenerator(this._backend);

  /// Creates an ephemeral certificate chain with the libp2p extension.
  ///
  /// [hostIdentityPrivateKey] is the host's long-term Ed25519 private key
  /// used to sign the [SignedKey].
  /// [hostPublicKeyBytes] is the corresponding raw public key bytes.
  /// [notBefore] and [notAfter] define the certificate validity window.
  Future<CertificateChain> generate({
    required SecretKey hostIdentityPrivateKey,
    required List<int> hostPublicKeyBytes,
    DateTime? notBefore,
    DateTime? notAfter,
  }) async {
    final nb = notBefore ?? DateTime.now();
    final na = notAfter ?? DateTime.now().add(const Duration(days: 1));

    // 1. Generate ephemeral ECDSA P-256 key pair.
    final ephemeralKeyPair = await _backend.ecdsaP256GenerateKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.publicKey;
    final ephemeralPrivateKey = await ephemeralKeyPair.secretKey;

    // 2. Build the SubjectPublicKeyInfo DER for the ephemeral certificate key.
    // This is needed both for the certificate and for the libp2p signature.
    final spki = _buildSubjectPublicKeyInfo(ephemeralPublicKey.bytes);
    final spkiDer = spki.encodedBytes;

    // 3. Sign libp2p-tls-handshake: || SubjectPublicKeyInfo_DER with the host
    // identity key per the libp2p TLS specification.
    final handshakeMessage = Uint8List.fromList([
      ..._utf8Bytes('libp2p-tls-handshake:'),
      ...spkiDer,
    ]);
    final identitySignature =
        await _backend.ed25519Sign(hostIdentityPrivateKey, handshakeMessage);

    // 4. Build the libp2p extension.
    final signedKey = SignedKey(
      publicKey: Libp2pPublicKey(
        type: Libp2pKeyType.ed25519,
        data: Uint8List.fromList(hostPublicKeyBytes),
      ),
      signature: Uint8List.fromList(identitySignature),
    );
    final libp2pExt = Libp2pExtension(signedKey: signedKey);
    final libp2pExtBytes = libp2pExt.serialize();

    // 5. Build X.509 TBSCertificate.
    final tbs = _buildTbsCertificate(
      ephemeralPublicKey: ephemeralPublicKey.bytes,
      notBefore: nb,
      notAfter: na,
      libp2pExtensionBytes: libp2pExtBytes,
    );

    // 6. Sign the TBS certificate with the ephemeral ECDSA private key.
    final tbsSignature = await _backend.ecdsaP256Sign(
      ephemeralPrivateKey,
      tbs.encodedBytes,
    );

    // 7. Build the outer certificate.
    final cert = _buildCertificate(tbs, tbsSignature);

    // 8. Parse into CertificateInfo and wrap in a chain.
    final certInfo = parseCertificate(cert.encodedBytes);
    return CertificateChain([certInfo]);
  }

  // -------------------------------------------------------------------------
  // ASN.1 helpers
  // -------------------------------------------------------------------------

  ASN1Sequence _buildTbsCertificate({
    required List<int> ephemeralPublicKey,
    required DateTime notBefore,
    required DateTime notAfter,
    required Uint8List libp2pExtensionBytes,
  }) {
    // Version [0] EXPLICIT INTEGER 2
    final versionInt = ASN1Integer.fromInt(2);
    final versionBytes = Uint8List.fromList([
      0xA0,
      ...ASN1Object.encodeLength(versionInt.encodedBytes.length),
      ...versionInt.encodedBytes,
    ]);
    final version = ASN1Object.fromBytes(versionBytes);

    // SerialNumber (INTEGER 1)
    final serialNumber = ASN1Integer.fromInt(1);

    // Signature Algorithm: ECDSA with SHA-256
    final sigAlg = _buildEcdsaSha256AlgorithmIdentifier();

    // Issuer / Subject: empty RDNSequence (minimal)
    final name = ASN1Sequence();

    // Validity
    final validity = _buildValidity(notBefore, notAfter);

    // SubjectPublicKeyInfo for ECDSA P-256
    final spki = _buildSubjectPublicKeyInfo(ephemeralPublicKey);

    // Extensions [3] EXPLICIT SEQUENCE { Extension }
    final libp2pOid = ASN1ObjectIdentifier.fromComponents([
      1,
      3,
      6,
      1,
      4,
      1,
      53594,
      1,
      1,
    ]);
    final extValue = ASN1OctetString(libp2pExtensionBytes);
    final extSeq = ASN1Sequence()..elements.addAll([libp2pOid, extValue]);
    final extensionsSeq = ASN1Sequence()..elements.add(extSeq);
    final wrapperBytes = Uint8List.fromList([
      0xA3,
      ...ASN1Object.encodeLength(extensionsSeq.encodedBytes.length),
      ...extensionsSeq.encodedBytes,
    ]);
    final extensions = ASN1Object.fromBytes(wrapperBytes);

    return ASN1Sequence()
      ..elements.addAll([
        version,
        serialNumber,
        sigAlg,
        name,
        validity,
        name,
        spki,
        extensions,
      ]);
  }

  ASN1Sequence _buildCertificate(
    ASN1Sequence tbs,
    List<int> signature,
  ) {
    final sigAlg = _buildEcdsaSha256AlgorithmIdentifier();

    // DER-encode the raw ECDSA signature (r || s) as SEQUENCE { INTEGER r, INTEGER s }
    final r = ASN1Integer(
      ASN1Integer.decodeBigInt(Uint8List.fromList(signature.sublist(0, 32))),
    );
    final s = ASN1Integer(
      ASN1Integer.decodeBigInt(Uint8List.fromList(signature.sublist(32, 64))),
    );
    final ecdsaSig = ASN1Sequence()..elements.addAll([r, s]);

    // BIT STRING with 0 unused bits
    final sigBitString = ASN1BitString(
      ecdsaSig.encodedBytes,
      unusedbits: 0,
    );

    return ASN1Sequence()..elements.addAll([tbs, sigAlg, sigBitString]);
  }

  ASN1Sequence _buildEcdsaSha256AlgorithmIdentifier() {
    final oid =
        ASN1ObjectIdentifier.fromComponents([1, 2, 840, 10045, 4, 3, 2]);
    final nullParam = ASN1Null();
    return ASN1Sequence()..elements.addAll([oid, nullParam]);
  }

  ASN1Sequence _buildSubjectPublicKeyInfo(List<int> publicKey) {
    // AlgorithmIdentifier: ecPublicKey + prime256v1
    final ecOid = ASN1ObjectIdentifier.fromComponents([1, 2, 840, 10045, 2, 1]);
    final curveOid =
        ASN1ObjectIdentifier.fromComponents([1, 2, 840, 10045, 3, 1, 7]);
    final algorithmId = ASN1Sequence()..elements.addAll([ecOid, curveOid]);

    // BIT STRING with 0 unused bits prefix + uncompressed point
    final keyBitString = ASN1BitString(
      Uint8List.fromList(publicKey),
      unusedbits: 0,
    );

    return ASN1Sequence()..elements.addAll([algorithmId, keyBitString]);
  }

  ASN1Sequence _buildValidity(DateTime notBefore, DateTime notAfter) {
    final nb = ASN1UtcTime(notBefore);
    final na = ASN1UtcTime(notAfter);
    return ASN1Sequence()..elements.addAll([nb, na]);
  }

  static List<int> _utf8Bytes(String value) => utf8.encode(value);
}

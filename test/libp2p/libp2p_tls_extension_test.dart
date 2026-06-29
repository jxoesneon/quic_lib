import 'dart:typed_data';

import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_chain.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:quic_lib/src/crypto/tls/encrypted_extensions.dart';
import 'package:quic_lib/src/crypto/tls/x509_parser.dart';
import 'package:quic_lib/src/libp2p/libp2p_certificate_generator.dart';
import 'package:quic_lib/src/libp2p/libp2p_tls_extension.dart';
import 'package:quic_lib/src/libp2p/peer_id.dart';
import 'package:test/test.dart';

import '../helpers/minimal_cert.dart' as helper;

void main() {
  group('SignedKey', () {
    test('serialize and parse round-trip', () {
      final publicKey = Libp2pPublicKey(
        type: Libp2pKeyType.ed25519,
        data: Uint8List.fromList([1, 2, 3, 4, 5]),
      );
      final signature = Uint8List.fromList([10, 20, 30, 40, 50]);

      final signedKey = SignedKey(
        publicKey: publicKey,
        signature: signature,
      );

      final serialized = signedKey.serialize();
      final parsed = SignedKey.parse(serialized);

      expect(parsed.publicKey.type, equals(publicKey.type));
      expect(parsed.publicKey.data, equals(publicKey.data));
      expect(parsed.signature, equals(signature));
    });

    test('parse throws on missing fields', () {
      final badBytes = Uint8List.fromList([0x0A, 0x03, 0x01, 0x02, 0x03]);
      expect(() => SignedKey.parse(badBytes), throwsFormatException);
    });
  });

  group('Libp2pExtension', () {
    test('serialize and parse round-trip', () {
      final signedKey = SignedKey(
        publicKey: Libp2pPublicKey(
          type: Libp2pKeyType.ed25519,
          data: Uint8List.fromList([0xAB, 0xCD, 0xEF]),
        ),
        signature: Uint8List.fromList([0x12, 0x34, 0x56, 0x78]),
      );

      final ext = Libp2pExtension(signedKey: signedKey);
      final serialized = ext.serialize();
      final parsed = Libp2pExtension.parse(serialized);

      expect(parsed.signedKey.publicKey.type, equals(signedKey.publicKey.type));
      expect(parsed.signedKey.publicKey.data, equals(signedKey.publicKey.data));
      expect(parsed.signedKey.signature, equals(signedKey.signature));
    });

    test('OID constant is correct', () {
      expect(Libp2pExtension.oid, equals('1.3.6.1.4.1.53594.1.1'));
    });
  });

  group('PeerId fromPublicKey', () {
    test('derives consistent PeerId from public key bytes', () async {
      final publicKey = List<int>.generate(32, (i) => i);
      final peerId = await PeerId.fromPublicKey(publicKey);

      expect(peerId.bytes.length, equals(34));
      expect(peerId.bytes[0], equals(0x12)); // sha2-256 multihash code
      expect(peerId.bytes[1], equals(0x20)); // 32 bytes

      final peerId2 = await PeerId.fromPublicKey(publicKey);
      expect(peerId, equals(peerId2));
    });

    test('different public keys yield different PeerIds', () async {
      final pk1 = List<int>.generate(32, (i) => i);
      final pk2 = List<int>.generate(32, (i) => i + 1);

      final peerId1 = await PeerId.fromPublicKey(pk1);
      final peerId2 = await PeerId.fromPublicKey(pk2);

      expect(peerId1, isNot(equals(peerId2)));
    });
  });

  group('Libp2pCertificateGenerator', () {
    late CryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    test('generates a parseable certificate with the libp2p extension',
        () async {
      // Generate a host Ed25519 identity key pair.
      final hostKeyPair = await backend.ed25519GenerateKeyPair();
      final hostPublicKey = await hostKeyPair.publicKey;

      // Generate the ephemeral certificate.
      final generator = Libp2pCertificateGenerator(backend);
      final chain = await generator.generate(
        hostIdentityPrivateKey: await hostKeyPair.secretKey,
        hostPublicKeyBytes: hostPublicKey.bytes,
      );

      expect(chain.certs.length, equals(1));

      // Parse the certificate and extract the extension.
      final certInfo = chain.certs.first;
      final x509 = parseX509(certInfo.rawBytes);
      expect(x509.extensions.containsKey(Libp2pExtension.oid), isTrue);
      final ext = parseLibp2pExtension(x509);

      expect(ext, isNotNull);
      expect(ext!.signedKey.publicKey.type, equals(Libp2pKeyType.ed25519));
      expect(ext.signedKey.publicKey.data, equals(hostPublicKey.bytes));
    });

    test('generated certificate passes verifyLibp2pSignature', () async {
      // Generate a host Ed25519 identity key pair.
      final hostKeyPair = await backend.ed25519GenerateKeyPair();
      final hostPublicKey = await hostKeyPair.publicKey;

      // Derive the expected PeerId.
      final expectedPeerId = await PeerId.fromPublicKey(hostPublicKey.bytes);

      // Generate the ephemeral certificate.
      final generator = Libp2pCertificateGenerator(backend);
      final chain = await generator.generate(
        hostIdentityPrivateKey: await hostKeyPair.secretKey,
        hostPublicKeyBytes: hostPublicKey.bytes,
      );

      // Verify the libp2p signature and PeerId.
      final valid = await chain.verifyLibp2pSignature(
        expectedPeerId,
        backend,
      );
      expect(valid, isTrue);
    });

    test('verifyLibp2pSignature fails with wrong expected PeerId', () async {
      // Generate host identity.
      final hostKeyPair = await backend.ed25519GenerateKeyPair();
      final hostPublicKey = await hostKeyPair.publicKey;

      // Wrong PeerId.
      final wrongPeerId = await PeerId.fromPublicKey(
        List<int>.generate(32, (i) => 0xFF),
      );

      final generator = Libp2pCertificateGenerator(backend);
      final chain = await generator.generate(
        hostIdentityPrivateKey: await hostKeyPair.secretKey,
        hostPublicKeyBytes: hostPublicKey.bytes,
      );

      final valid = await chain.verifyLibp2pSignature(
        wrongPeerId,
        backend,
      );
      expect(valid, isFalse);
    });

    test('extractLibp2pExtension returns null for chain without extension', () {
      // Use the existing minimal certificate helper (no libp2p extension).
      final minimalCert = CertificateInfo(
        rawBytes: helper.buildMinimalCert(),
        subjectPublicKey: const [],
        algorithm: 'ecdsaP256',
        notBefore: DateTime(2020, 1, 1),
        notAfter: DateTime(2030, 1, 1),
        subjectName: 'CN=test',
      );
      final chain = CertificateChain([minimalCert]);
      expect(chain.extractLibp2pExtension(), isNull);
    });
  });

  group('ALPN in ClientHello', () {
    test('alpnProtocols are included in serialized ClientHello', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [],
        alpnProtocols: ['libp2p'],
      );

      final bytes = clientHello.serialize();
      expect(bytes, isNotEmpty);

      // Find the ALPN extension (0x0010) in the extension list.
      // Extensions start after: legacy_version(2) + random(32) +
      // session_id_length(1) + session_id(0) + cipher_suites_length(2) +
      // cipher_suites(2) + compression_methods_length(1) + compression(1) = 41
      // extensions_length at offset 41
      final extLen = (bytes[41] << 8) | bytes[42];
      expect(extLen, greaterThan(0));

      var offset = 43;
      var foundAlpn = false;
      while (offset + 4 <= bytes.length) {
        final int extType = ((bytes[offset] << 8) | bytes[offset + 1]) as int;
        final int extDataLen =
            ((bytes[offset + 2] << 8) | bytes[offset + 3]) as int;
        if (extType == 0x0010) {
          foundAlpn = true;
          // ALPN data: uint16 list_len + uint8 name_len + name
          final alpnListLen = (bytes[offset + 4] << 8) | bytes[offset + 5];
          expect(alpnListLen, greaterThan(0));
          final nameLen = bytes[offset + 6];
          final name = String.fromCharCodes(
            bytes.sublist(offset + 7, offset + 7 + nameLen),
          );
          expect(name, equals('libp2p'));
          break;
        }
        offset += 4 + extDataLen;
      }
      expect(foundAlpn, isTrue);
    });
  });

  group('ALPN in EncryptedExtensions', () {
    test('alpnProtocol extracts negotiated protocol', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x0010, data: [
          0x06, // name length
          0x6c, 0x69, 0x62, 0x70, 0x32, 0x70, // 'libp2p'
        ]),
      ]);

      expect(ee.alpnProtocol, equals('libp2p'));
    });

    test('alpnProtocol returns null when ALPN is absent', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x002b, data: [0x03, 0x04]),
      ]);

      expect(ee.alpnProtocol, isNull);
    });
  });
}

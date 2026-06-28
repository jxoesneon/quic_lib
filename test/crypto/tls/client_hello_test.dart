import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';

void main() {
  group('ClientHello', () {
    final random = List<int>.generate(32, (i) => i);
    final cipherSuites = <CipherSuite>[
      CipherSuite.tlsAes128GcmSha256,
      CipherSuite.tlsChacha20Poly1305Sha256,
    ];
    final extensions = <TlsExtension>[
      TlsExtension(type: 0x002b, data: [0x03, 0x04]),
    ];

    final clientHello = ClientHello(
      random: random,
      cipherSuites: cipherSuites,
      extensions: extensions,
    );

    test('serialize produces non-empty bytes', () {
      final bytes = clientHello.serialize();
      expect(bytes, isNotEmpty);
    });

    test('first bytes are legacy version 0x0303', () {
      final bytes = clientHello.serialize();
      expect(bytes.length, greaterThanOrEqualTo(2));
      expect(bytes[0], equals(0x03));
      expect(bytes[1], equals(0x03));
    });

    test('random is 32 bytes', () {
      final bytes = clientHello.serialize();
      final extracted = bytes.sublist(2, 34);
      expect(extracted, equals(random));
    });

    test('cipher suites included', () {
      final bytes = clientHello.serialize();
      // offset after legacy_version(2) + random(32) + session_id_length(1) = 35
      // session_id is empty, so cipher_suites_length starts at 35
      final csLen = (bytes[35] << 8) | bytes[36];
      expect(csLen, equals(cipherSuites.length * 2));
      // first cipher suite at offset 37
      expect(bytes[37], equals(0x13));
      expect(bytes[38], equals(0x01));
      // second cipher suite at offset 39
      expect(bytes[39], equals(0x13));
      expect(bytes[40], equals(0x03));
    });

    test('extensions included', () {
      final bytes = clientHello.serialize();
      // Compression methods length is at 41, data at 42.
      // Extensions length starts at offset 43.
      final extLen = (bytes[43] << 8) | bytes[44];
      expect(extLen, greaterThan(0));
      // first extension type at 45-46
      expect(bytes[45], equals(0x00));
      expect(bytes[46], equals(0x2b));
      // extension data length at 47-48
      final extDataLen = (bytes[47] << 8) | bytes[48];
      expect(extDataLen, equals(2));
      // extension data at 49-50
      expect(bytes[49], equals(0x03));
      expect(bytes[50], equals(0x04));
    });
  });
}

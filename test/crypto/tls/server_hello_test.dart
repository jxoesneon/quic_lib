import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/server_hello.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart'
    show CipherSuite, TlsExtension;

void main() {
  group('ServerHello', () {
    final random = List<int>.generate(32, (i) => i);
    final cipherSuite = CipherSuite.tlsAes128GcmSha256;
    final extensions = <TlsExtension>[
      TlsExtension(type: 0x002b, data: [0x03, 0x04]),
    ];

    final serverHello = ServerHello(
      random: random,
      cipherSuite: cipherSuite,
      extensions: extensions,
    );

    test('serialize produces non-empty bytes', () {
      final bytes = serverHello.serialize();
      expect(bytes, isNotEmpty);
    });

    test('first bytes are legacy version 0x0303', () {
      final bytes = serverHello.serialize();
      expect(bytes.length, greaterThanOrEqualTo(2));
      expect(bytes[0], equals(0x03));
      expect(bytes[1], equals(0x03));
    });

    test('random is 32 bytes', () {
      final bytes = serverHello.serialize();
      final extracted = bytes.sublist(2, 34);
      expect(extracted, equals(random));
    });

    test('cipher suite included', () {
      final bytes = serverHello.serialize();
      // offset after legacy_version(2) + random(32) + session_id_echo_length(1) = 35
      // session_id_echo is empty, so cipher_suite starts at 35
      expect(bytes[35], equals(0x13));
      expect(bytes[36], equals(0x01));
    });

    test('extensions included', () {
      final bytes = serverHello.serialize();
      // Compression method is at 37.
      // Extensions length starts at offset 38.
      final extLen = (bytes[38] << 8) | bytes[39];
      expect(extLen, greaterThan(0));
      // first extension type at 40-41
      expect(bytes[40], equals(0x00));
      expect(bytes[41], equals(0x2b));
      // extension data length at 42-43
      final extDataLen = (bytes[42] << 8) | bytes[43];
      expect(extDataLen, equals(2));
      // extension data at 44-45
      expect(bytes[44], equals(0x03));
      expect(bytes[45], equals(0x04));
    });
  });
}

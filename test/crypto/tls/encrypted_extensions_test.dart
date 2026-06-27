import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dart_quic/src/crypto/tls/client_hello.dart';
import 'package:dart_quic/src/crypto/tls/encrypted_extensions.dart';

void main() {
  group('EncryptedExtensions', () {
    test('serialize round-trip with parse', () {
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0010, data: [0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]), // ALPN
      ];

      final ee = EncryptedExtensions(extensions: extensions);
      final bytes = ee.serialize();
      final parsed = EncryptedExtensions.parse(bytes);

      expect(parsed.extensions.length, equals(1));
      expect(parsed.extensions[0].type, equals(0x0010));
      expect(parsed.extensions[0].data, equals(extensions[0].data));
    });

    test('empty extensions list works', () {
      final ee = EncryptedExtensions(extensions: <TlsExtension>[]);
      final bytes = ee.serialize();

      expect(bytes.length, equals(2));
      expect(bytes[0], equals(0x00));
      expect(bytes[1], equals(0x00));

      final parsed = EncryptedExtensions.parse(bytes);
      expect(parsed.extensions, isEmpty);
    });

    test('multiple extensions preserved', () {
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0010, data: [0x00, 0x02, 0x68, 0x32]), // ALPN h2
        TlsExtension(type: 0x002b, data: [0x03, 0x04]), // supported_versions TLS 1.3
        TlsExtension(type: 0x0033, data: [0x00, 0x01, 0x00]), // key_share minimal
      ];

      final ee = EncryptedExtensions(extensions: extensions);
      final bytes = ee.serialize();
      final parsed = EncryptedExtensions.parse(bytes);

      expect(parsed.extensions.length, equals(3));

      for (var i = 0; i < extensions.length; i++) {
        expect(parsed.extensions[i].type, equals(extensions[i].type));
        expect(parsed.extensions[i].data, equals(extensions[i].data));
      }
    });

    test('parse rejects truncated header', () {
      final bytes = Uint8List.fromList([0x00]);
      expect(
        () => EncryptedExtensions.parse(bytes),
        throwsArgumentError,
      );
    });

    test('parse rejects length exceeding buffer', () {
      final bytes = Uint8List.fromList([0x00, 0x04, 0x00, 0x01]);
      expect(
        () => EncryptedExtensions.parse(bytes),
        throwsArgumentError,
      );
    });
  });
}

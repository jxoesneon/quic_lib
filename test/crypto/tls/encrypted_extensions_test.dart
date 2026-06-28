import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:quic_lib/src/crypto/tls/encrypted_extensions.dart';

void main() {
  group('EncryptedExtensions', () {
    test('serialize round-trip with parse', () {
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0010, data: [
          0x08,
          0x68,
          0x74,
          0x74,
          0x70,
          0x2f,
          0x31,
          0x2e,
          0x31
        ]), // ALPN
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
        TlsExtension(
            type: 0x002b, data: [0x03, 0x04]), // supported_versions TLS 1.3
        TlsExtension(
            type: 0x0033, data: [0x00, 0x01, 0x00]), // key_share minimal
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

    test('parse rejects extension header truncated', () {
      // extensions_length = 3, but we need at least 4 bytes for one extension header
      final bytes = Uint8List.fromList([
        0x00, 0x03, // extensions_length = 3
        0x00, 0x01, // type (2 bytes)
        0x00, // only 1 byte of length, truncated
      ]);
      expect(
        () => EncryptedExtensions.parse(bytes),
        throwsArgumentError,
      );
    });

    test('parse rejects extension data truncated', () {
      // extensions_length = 4, extension type=0x0001, length=0x0005 but only 0 bytes of data
      final bytes = Uint8List.fromList([
        0x00, 0x04, // extensions_length = 4
        0x00, 0x01, // type = 1
        0x00, 0x05, // length = 5 (but no data follows)
      ]);
      expect(
        () => EncryptedExtensions.parse(bytes),
        throwsArgumentError,
      );
    });

    test('parse accepts trailing bytes outside extension block', () {
      // The parser only validates extensions_length bytes; trailing bytes
      // after the declared extension block are ignored.
      final bytes = Uint8List.fromList([
        0x00, 0x06, // extensions_length = 6
        0x00, 0x01, // type = 1
        0x00, 0x02, // length = 2
        0xAB, 0xCD, // data
        0xFF, 0xFF, // trailing bytes
      ]);
      final parsed = EncryptedExtensions.parse(bytes);
      expect(parsed.extensions.length, equals(1));
      expect(parsed.extensions[0].type, equals(0x0001));
      expect(parsed.extensions[0].data, equals([0xAB, 0xCD]));
    });

    test('serialize empty extensions list', () {
      final ee = EncryptedExtensions(extensions: <TlsExtension>[]);
      final bytes = ee.serialize();
      expect(bytes.length, equals(2));
      expect(bytes[0], equals(0x00));
      expect(bytes[1], equals(0x00));
    });

    test('serialize and parse single extension with empty data', () {
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0001, data: <int>[]),
      ];
      final ee = EncryptedExtensions(extensions: extensions);
      final bytes = ee.serialize();
      final parsed = EncryptedExtensions.parse(bytes);

      expect(parsed.extensions.length, equals(1));
      expect(parsed.extensions[0].type, equals(0x0001));
      expect(parsed.extensions[0].data, isEmpty);
    });

    test('serialize and parse large extension data', () {
      final largeData = List<int>.generate(256, (i) => i & 0xFF);
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0029, data: largeData),
      ];
      final ee = EncryptedExtensions(extensions: extensions);
      final bytes = ee.serialize();
      final parsed = EncryptedExtensions.parse(bytes);

      expect(parsed.extensions.length, equals(1));
      expect(parsed.extensions[0].type, equals(0x0029));
      expect(parsed.extensions[0].data, equals(largeData));
    });

    test('parse with exactly 2 bytes (empty extensions)', () {
      final bytes = Uint8List.fromList([0x00, 0x00]);
      final parsed = EncryptedExtensions.parse(bytes);
      expect(parsed.extensions, isEmpty);
    });

    test('parse multiple extensions round-trip', () {
      final extensions = <TlsExtension>[
        TlsExtension(type: 0x0010, data: [0x00, 0x02, 0x68, 0x32]),
        TlsExtension(type: 0x002b, data: [0x03, 0x04]),
        TlsExtension(type: 0x0033, data: [0x00, 0x01, 0x00]),
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
  });
}

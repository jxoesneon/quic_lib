import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart';
import 'package:quic_lib/src/crypto/tls/encrypted_extensions.dart';

void main() {
  group('ClientHello SNI extension', () {
    test('includes SNI when serverName is provided', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [],
        serverName: 'example.com',
      );

      final bytes = clientHello.serialize();

      // Find the SNI extension (0x0000) in the extension list.
      // Extensions start after: legacy_version(2) + random(32) +
      // session_id_length(1) + session_id(0) + cipher_suites_length(2) +
      // cipher_suites(2) + compression_methods_length(1) + compression(1) = 41
      final extLen = (bytes[41] << 8) | bytes[42];
      expect(extLen, greaterThan(0));

      var offset = 43;
      var foundSni = false;
      while (offset + 4 <= bytes.length) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        final extDataLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (extType == 0x0000) {
          foundSni = true;
          // SNI data: uint16 list_len + uint8 name_type + uint16 name_len + name
          final listLen = (bytes[offset + 4] << 8) | bytes[offset + 5];
          expect(listLen, greaterThan(0));
          final nameType = bytes[offset + 6];
          expect(nameType, equals(0)); // host_name
          final nameLen = (bytes[offset + 7] << 8) | bytes[offset + 8];
          final name = String.fromCharCodes(
            bytes.sublist(offset + 9, offset + 9 + nameLen),
          );
          expect(name, equals('example.com'));
          break;
        }
        offset += 4 + extDataLen;
      }
      expect(foundSni, isTrue);
    });

    test('does not duplicate SNI if already in extensions', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [
          TlsExtension(
              type: 0x0000,
              data: [0x00, 0x05, 0x00, 0x00, 0x03, 0x66, 0x6f, 0x6f]),
        ],
        serverName: 'example.com',
      );

      final bytes = clientHello.serialize();
      var sniCount = 0;
      var offset = 43;
      final extLen = (bytes[41] << 8) | bytes[42];
      final end = 43 + extLen;
      while (offset + 4 <= end) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        final extDataLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (extType == 0x0000) sniCount++;
        offset += 4 + extDataLen;
      }
      expect(sniCount, equals(1));
    });
  });

  group('ClientHello supported_groups extension', () {
    test('includes default groups when not provided manually', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [],
      );

      final bytes = clientHello.serialize();

      var offset = 43;
      final extLen = (bytes[41] << 8) | bytes[42];
      final end = 43 + extLen;
      var found = false;
      while (offset + 4 <= end) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        final extDataLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (extType == 0x000a) {
          found = true;
          final listLen = (bytes[offset + 4] << 8) | bytes[offset + 5];
          expect(listLen, equals(4)); // 2 groups * 2 bytes
          final g1 = (bytes[offset + 6] << 8) | bytes[offset + 7];
          final g2 = (bytes[offset + 8] << 8) | bytes[offset + 9];
          expect(g1, equals(0x001d)); // x25519
          expect(g2, equals(0x0017)); // secp256r1
          break;
        }
        offset += 4 + extDataLen;
      }
      expect(found, isTrue);
    });

    test('uses custom supportedGroups', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [],
        supportedGroups: [0x0017],
      );

      final bytes = clientHello.serialize();

      var offset = 43;
      final extLen = (bytes[41] << 8) | bytes[42];
      final end = 43 + extLen;
      var found = false;
      while (offset + 4 <= end) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        final extDataLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (extType == 0x000a) {
          found = true;
          final listLen = (bytes[offset + 4] << 8) | bytes[offset + 5];
          expect(listLen, equals(2)); // 1 group * 2 bytes
          final g1 = (bytes[offset + 6] << 8) | bytes[offset + 7];
          expect(g1, equals(0x0017));
          break;
        }
        offset += 4 + extDataLen;
      }
      expect(found, isTrue);
    });

    test('does not duplicate supported_groups if already in extensions', () {
      final clientHello = ClientHello(
        random: List<int>.generate(32, (i) => i),
        cipherSuites: [CipherSuite.tlsAes128GcmSha256],
        extensions: [
          TlsExtension(type: 0x000a, data: [0x00, 0x02, 0x00, 0x17]),
        ],
        supportedGroups: [0x001d, 0x0017],
      );

      final bytes = clientHello.serialize();
      var count = 0;
      var offset = 43;
      final extLen = (bytes[41] << 8) | bytes[42];
      final end = 43 + extLen;
      while (offset + 4 <= end) {
        final extType = (bytes[offset] << 8) | bytes[offset + 1];
        final extDataLen = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (extType == 0x000a) count++;
        offset += 4 + extDataLen;
      }
      expect(count, equals(1));
    });
  });

  group('EncryptedExtensions supportedGroups getter', () {
    test('extracts supported groups', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x000a, data: [
          0x00, 0x04, // list length = 4
          0x00, 0x17, // secp256r1
          0x00, 0x1d, // x25519
        ]),
      ]);

      expect(ee.supportedGroups, equals([0x0017, 0x001d]));
    });

    test('returns empty list when extension is absent', () {
      final ee = EncryptedExtensions(extensions: []);
      expect(ee.supportedGroups, isEmpty);
    });

    test('returns empty list on malformed data', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x000a, data: [0x00, 0x10]), // list_len > data
      ]);
      expect(ee.supportedGroups, isEmpty);
    });
  });

  group('EncryptedExtensions selectedServerName getter', () {
    test('extracts server name', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x0000, data: [
          0x00, 0x0e, // list length = 14
          0x00, // name_type = host_name
          0x00, 0x0b, // name_length = 11
          ...'example.com'.codeUnits,
        ]),
      ]);

      expect(ee.selectedServerName, equals('example.com'));
    });

    test('returns null when extension is absent', () {
      final ee = EncryptedExtensions(extensions: []);
      expect(ee.selectedServerName, isNull);
    });

    test('returns null on malformed data', () {
      final ee = EncryptedExtensions(extensions: [
        TlsExtension(type: 0x0000, data: [0x00, 0x10]), // list_len > data
      ]);
      expect(ee.selectedServerName, isNull);
    });
  });
}

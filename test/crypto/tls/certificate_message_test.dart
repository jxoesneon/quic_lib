import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/client_hello.dart' show TlsExtension;

void main() {
  group('CertificateMessage', () {
    test('serialize round-trip with parse', () {
      final entry = CertificateEntry(
        certData: [0x01, 0x02, 0x03, 0x04],
        extensions: [
          TlsExtension(type: 0x000b, data: [0xAA, 0xBB]),
        ],
      );
      final original = CertificateMessage(entries: [entry]);

      final serialized = original.serialize();
      final parsed = CertificateMessage.parse(serialized);

      expect(parsed.requestContext, isEmpty);
      expect(parsed.entries.length, equals(1));
      expect(parsed.entries[0].certData, equals([0x01, 0x02, 0x03, 0x04]));
      expect(parsed.entries[0].extensions.length, equals(1));
      expect(parsed.entries[0].extensions[0].type, equals(0x000b));
      expect(parsed.entries[0].extensions[0].data, equals([0xAA, 0xBB]));
    });

    test('empty entries list works', () {
      final original = CertificateMessage(entries: []);

      final serialized = original.serialize();
      expect(serialized.length, equals(4));
      expect(serialized[0], equals(0)); // request_context_length = 0
      expect(serialized[1], equals(0)); // certificates_length high byte
      expect(serialized[2], equals(0)); // certificates_length mid byte
      expect(serialized[3], equals(0)); // certificates_length low byte

      final parsed = CertificateMessage.parse(serialized);
      expect(parsed.entries, isEmpty);
      expect(parsed.requestContext, isEmpty);
    });

    test('multiple entries preserved', () {
      final original = CertificateMessage(entries: [
        CertificateEntry(certData: [0x01, 0x02]),
        CertificateEntry(certData: [0x03, 0x04, 0x05]),
        CertificateEntry(certData: [0x06]),
      ]);

      final serialized = original.serialize();
      final parsed = CertificateMessage.parse(serialized);

      expect(parsed.entries.length, equals(3));
      expect(parsed.entries[0].certData, equals([0x01, 0x02]));
      expect(parsed.entries[1].certData, equals([0x03, 0x04, 0x05]));
      expect(parsed.entries[2].certData, equals([0x06]));
    });

    test('request context preserved', () {
      final original = CertificateMessage(
        requestContext: [0xAB, 0xCD],
        entries: [
          CertificateEntry(certData: [0xFF]),
        ],
      );

      final serialized = original.serialize();
      final parsed = CertificateMessage.parse(serialized);

      expect(parsed.requestContext, equals([0xAB, 0xCD]));
      expect(parsed.entries.length, equals(1));
      expect(parsed.entries[0].certData, equals([0xFF]));
    });
  });
}

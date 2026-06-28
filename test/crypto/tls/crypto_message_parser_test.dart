import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:test/test.dart';

void main() {
  group('parseMessageType', () {
    test('returns null for empty message', () {
      expect(parseMessageType(Uint8List(0)), isNull);
    });

    test('returns null for unknown type', () {
      expect(parseMessageType(Uint8List.fromList([0xff])), isNull);
    });

    test('parses clientHello (0x01)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x01])),
        equals(TlsHandshakeType.clientHello),
      );
    });

    test('parses serverHello (0x02)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x02])),
        equals(TlsHandshakeType.serverHello),
      );
    });

    test('parses encryptedExtensions (0x08)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x08])),
        equals(TlsHandshakeType.encryptedExtensions),
      );
    });

    test('parses certificate (0x0b)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x0b])),
        equals(TlsHandshakeType.certificate),
      );
    });

    test('parses certificateVerify (0x0f)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x0f])),
        equals(TlsHandshakeType.certificateVerify),
      );
    });

    test('parses finished (0x14)', () {
      expect(
        parseMessageType(Uint8List.fromList([0x14])),
        equals(TlsHandshakeType.finished),
      );
    });
  });

  group('parseMessage', () {
    test('parses full message with correct type and payload', () {
      final payload = Uint8List.fromList([1, 2, 3, 4, 5]);
      final message = Uint8List.fromList([
        0x01, // clientHello
        0x00, 0x00, 0x05, // length = 5
        ...payload,
      ]);

      final result = parseMessage(message);

      expect(result.type, equals(TlsHandshakeType.clientHello));
      expect(result.payload, equals(payload));
    });

    test('parses serverHello message', () {
      final payload = Uint8List.fromList([0xab, 0xcd]);
      final message = Uint8List.fromList([
        0x02, // serverHello
        0x00, 0x00, 0x02, // length = 2
        ...payload,
      ]);

      final result = parseMessage(message);

      expect(result.type, equals(TlsHandshakeType.serverHello));
      expect(result.payload, equals(payload));
    });

    test('parses finished message', () {
      final payload = Uint8List.fromList(List.filled(32, 0x00));
      final message = Uint8List.fromList([
        0x14, // finished
        0x00, 0x00, 0x20, // length = 32
        ...payload,
      ]);

      final result = parseMessage(message);

      expect(result.type, equals(TlsHandshakeType.finished));
      expect(result.payload, equals(payload));
    });

    test('throws on empty message', () {
      expect(() => parseMessage(Uint8List(0)), throwsFormatException);
    });

    test('throws on incomplete length header', () {
      expect(
        () => parseMessage(Uint8List.fromList([0x01, 0x00, 0x00])),
        throwsFormatException,
      );
    });

    test('throws on truncated payload', () {
      final message = Uint8List.fromList([
        0x01, // clientHello
        0x00, 0x00, 0x05, // length = 5
        1, 2, // only 2 payload bytes
      ]);
      expect(() => parseMessage(message), throwsFormatException);
    });

    test('throws on unknown type', () {
      final message = Uint8List.fromList([
        0xff, // unknown
        0x00, 0x00, 0x01, // length = 1
        0x00,
      ]);
      expect(() => parseMessage(message), throwsFormatException);
    });
  });
}

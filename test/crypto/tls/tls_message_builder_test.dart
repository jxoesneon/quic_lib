import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:test/test.dart';

void main() {
  group('TlsMessageBuilder', () {
    group('buildClientHello', () {
      test('parseMessage returns correct type and non-empty payload', () {
        final random = Uint8List.fromList(List.generate(32, (i) => i));
        final legacySessionId = Uint8List(0);
        final cipherSuites = [0x1301, 0x1303];
        final extensions = <Uint8List>[
          Uint8List.fromList([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
        ];

        final message = TlsMessageBuilder.buildClientHello(
          random,
          legacySessionId,
          cipherSuites,
          extensions,
        );

        final result = parseMessage(message);
        expect(result.type, equals(TlsHandshakeType.clientHello));
        expect(result.payload, isNotEmpty);
      });

      test('build + parse round-trip preserves payload bytes', () {
        final random = Uint8List.fromList(List.generate(32, (i) => i));
        final legacySessionId = Uint8List.fromList([0x01, 0x02]);
        final cipherSuites = [0x1301];
        final extensions = <Uint8List>[
          Uint8List.fromList([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
        ];

        final message = TlsMessageBuilder.buildClientHello(
          random,
          legacySessionId,
          cipherSuites,
          extensions,
        );

        final result = parseMessage(message);

        // Verify payload structure
        expect(result.payload[0], equals(0x03)); // legacy version high
        expect(result.payload[1], equals(0x03)); // legacy version low
        expect(result.payload.sublist(2, 34), equals(random));
        expect(result.payload[34], equals(legacySessionId.length));
        expect(result.payload.sublist(35, 37), equals(legacySessionId));
      });
    });

    group('buildServerHello', () {
      test('parseMessage returns correct type', () {
        final random = Uint8List.fromList(List.generate(32, (i) => i + 1));
        final legacySessionId = Uint8List(0);
        final cipherSuite = 0x1301;
        final extensions = <Uint8List>[
          Uint8List.fromList([0x00, 0x33, 0x00, 0x02, 0xab, 0xcd]),
        ];

        final message = TlsMessageBuilder.buildServerHello(
          random,
          legacySessionId,
          cipherSuite,
          extensions,
        );

        final result = parseMessage(message);
        expect(result.type, equals(TlsHandshakeType.serverHello));
        expect(result.payload, isNotEmpty);
      });

      test('build + parse round-trip preserves payload bytes', () {
        final random = Uint8List.fromList(List.generate(32, (i) => 31 - i));
        final legacySessionId = Uint8List.fromList([0xab]);
        final cipherSuite = 0x1302;
        final extensions = <Uint8List>[
          Uint8List.fromList([0x00, 0x33, 0x00, 0x02, 0xab, 0xcd]),
        ];

        final message = TlsMessageBuilder.buildServerHello(
          random,
          legacySessionId,
          cipherSuite,
          extensions,
        );

        final result = parseMessage(message);

        expect(result.payload[0], equals(0x03));
        expect(result.payload[1], equals(0x03));
        expect(result.payload.sublist(2, 34), equals(random));
        // session id length at offset 34
        expect(result.payload[34], equals(1));
        expect(result.payload[35], equals(0xab));
        // cipher suite at offset 36
        expect(result.payload[36], equals(0x13));
        expect(result.payload[37], equals(0x02));
      });
    });

    group('buildFinished', () {
      test('parseMessage returns correct type and exact payload', () {
        final verifyData = Uint8List.fromList(List.generate(32, (i) => i));

        final message = TlsMessageBuilder.buildFinished(verifyData);

        final result = parseMessage(message);
        expect(result.type, equals(TlsHandshakeType.finished));
        expect(result.payload, equals(verifyData));
      });

      test('build + parse round-trip preserves payload bytes', () {
        final verifyData = Uint8List.fromList(
          List.generate(48, (i) => i * 2 % 256),
        );

        final message = TlsMessageBuilder.buildFinished(verifyData);

        final result = parseMessage(message);
        expect(result.payload, equals(verifyData));
        expect(result.payload.length, equals(48));
      });
    });
  });
}

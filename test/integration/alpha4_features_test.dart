import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/crypto/packet/packet_protector.dart';
import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/io/quic_endpoint.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Integration tests for alpha.4 features.
void main() {
  group('Header Protection Round-Trip', () {
    final aesHpKey = List<int>.filled(16, 0xAB);

    test('LongHeader packet apply + remove produces original header', () {
      final hp = HeaderProtection(hpKey: aesHpKey, isChaCha20: false);

      final version = 0x00000001;
      final packetType = 0x00; // Initial
      final dcid = [0x01, 0x02, 0x03];
      final scid = [0x04, 0x05];
      final token = <int>[];
      final pn = 42;
      final pnLen = 1;

      final firstByte = 0x80 | 0x40 | (packetType << 4) | (pnLen - 1);
      final builder = BytesBuilder();
      builder.addByte(firstByte);
      builder.addByte((version >> 24) & 0xFF);
      builder.addByte((version >> 16) & 0xFF);
      builder.addByte((version >> 8) & 0xFF);
      builder.addByte(version & 0xFF);
      builder.addByte(dcid.length);
      builder.add(dcid);
      builder.addByte(scid.length);
      builder.add(scid);
      builder.add(VarInt.encode(token.length));
      builder.add(token);

      final payload = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final length = pnLen + payload.length;
      builder.add(VarInt.encode(length));
      builder.addByte(pn & 0xFF);

      final header = Uint8List.fromList(builder.toBytes());

      final protected = hp.apply(header, payload);
      final unprotected = hp.remove(protected, payload);

      expect(unprotected, equals(header));
    });

    test('ShortHeader packet apply + remove produces original header', () {
      final hp = HeaderProtection(hpKey: aesHpKey, isChaCha20: false);

      final dcid = [0x01, 0x02, 0x03, 0x04];
      final pn = 0x1234;
      final pnLen = 2;
      final firstByte = 0x40 | (pnLen - 1);
      final header = Uint8List.fromList([
        firstByte,
        ...dcid,
        (pn >> 8) & 0xFF,
        pn & 0xFF,
      ]);
      final payload = Uint8List.fromList(List<int>.generate(32, (i) => i));

      final protected = hp.apply(header, payload);
      final unprotected = hp.remove(protected, payload);

      expect(unprotected, equals(header));
    });

    test('different samples produce different protected headers', () {
      final hp = HeaderProtection(hpKey: aesHpKey, isChaCha20: false);

      final header = Uint8List.fromList([0x40, 0x01, 0x02]);
      final payload1 = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final payload2 = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

      final protected1 = hp.apply(header, payload1);
      final protected2 = hp.apply(header, payload2);

      expect(protected1, isNot(equals(protected2)));
    });
  });

  group('Key Transition', () {
    final backend = DefaultCryptoBackend();

    PacketNumberSpaceKeys makeDummyKeys() {
      final protector = PacketProtector(
        backend: backend,
        aead: Aes128Gcm(),
        key: SimpleSecretKey(List<int>.filled(16, 0)),
        iv: List<int>.filled(12, 0),
      );
      final hp = HeaderProtection(
        hpKey: List<int>.filled(16, 0),
        isChaCha20: false,
      );
      return PacketNumberSpaceKeys(
        protector: protector,
        headerProtection: hp,
      );
    }

    test(
        'discardKeys(PacketNumberSpace.initial) removes Initial keys but keeps others',
        () async {
      final dcid = List<int>.filled(8, 0xAB);
      final keyManager = await KeyManager.deriveInitial(dcid, backend);

      // Install dummy Handshake keys.
      keyManager.installKeys(
        PacketNumberSpace.handshake,
        makeDummyKeys(),
      );

      expect(keyManager.hasKeysFor(PacketNumberSpace.initial), isTrue);
      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isTrue);

      keyManager.discardKeys(PacketNumberSpace.initial);

      expect(keyManager.hasKeysFor(PacketNumberSpace.initial), isFalse);
      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isTrue);
    });

    test('discardKeys(PacketNumberSpace.handshake) removes Handshake keys',
        () async {
      final dcid = List<int>.filled(8, 0xAB);
      final keyManager = await KeyManager.deriveInitial(dcid, backend);

      keyManager.installKeys(
        PacketNumberSpace.handshake,
        makeDummyKeys(),
      );

      keyManager.discardKeys(PacketNumberSpace.handshake);

      expect(keyManager.hasKeysFor(PacketNumberSpace.handshake), isFalse);
      expect(keyManager.hasKeysFor(PacketNumberSpace.initial), isTrue);
    });
  });

  group('TLS Message Parsing', () {
    test('parseMessage handles ClientHello type=1 with 3-byte payload', () {
      final payload = Uint8List.fromList([0xAA, 0xBB, 0xCC]);
      final message = Uint8List(4 + payload.length);
      message[0] = 0x01; // ClientHello
      message[1] = 0x00;
      message[2] = 0x00;
      message[3] = payload.length;
      message.setRange(4, message.length, payload);

      final result = parseMessage(message);

      expect(result.type, equals(TlsHandshakeType.clientHello));
      expect(result.payload, equals(payload));
    });

    test('parseMessage handles Finished type=20', () {
      final payload = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      final message = Uint8List(4 + payload.length);
      message[0] = 0x14; // Finished
      message[1] = 0x00;
      message[2] = 0x00;
      message[3] = payload.length;
      message.setRange(4, message.length, payload);

      final result = parseMessage(message);

      expect(result.type, equals(TlsHandshakeType.finished));
      expect(result.payload, equals(payload));
    });

    test('parseMessageType returns null for unknown types', () {
      final unknown = Uint8List.fromList([0xFF]);
      final type = parseMessageType(unknown);
      expect(type, isNull);
    });
  });

  group('Endpoint Connect', () {
    test('QuicEndpoint.bind creates an endpoint successfully', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(endpoint.close);
      expect(endpoint.localPort, greaterThan(0));
    });

    test('endpoint.connect scaffolds a QuicConnection', () async {
      final endpoint = await QuicEndpoint.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(endpoint.close);

      // TODO: Replace with full handshake test once QuicEndpoint.connect
      // is wired up end-to-end in a future alpha release.
      final conn = await endpoint.connect(InternetAddress.loopbackIPv4, 12345);
      expect(conn, isNotNull);
      expect(conn.state.toString(), contains('handshaking'));
    });
  });
}

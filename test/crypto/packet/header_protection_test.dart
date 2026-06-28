import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/wire/varint.dart';

void main() {
  group('HeaderProtection', () {
    final aesHpKey = List<int>.filled(16, 0xAB);
    final chachaHpKey = List<int>.filled(32, 0xCD);
    final backend = DefaultCryptoBackend();

    group('AES', () {
      test('apply/remove round-trip for a short header', () {
        final hp = HeaderProtection(
          hpKey: aesHpKey,
          isChaCha20: false,
        );

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

      test('apply/remove round-trip for a long header', () {
        final hp = HeaderProtection(
          hpKey: aesHpKey,
          isChaCha20: false,
        );

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

      test('different samples produce different masks', () {
        final hp = HeaderProtection(
          hpKey: aesHpKey,
          isChaCha20: false,
        );

        final header = Uint8List.fromList([0x40, 0x01, 0x02]);
        final payload1 = Uint8List.fromList(List<int>.generate(32, (i) => i));
        final payload2 =
            Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

        final protected1 = hp.apply(header, payload1);
        final protected2 = hp.apply(header, payload2);

        expect(protected1, isNot(equals(protected2)));
      });
    });

    group('ChaCha20', () {
      test('apply/remove round-trip for a short header', () {
        final hp = HeaderProtection(
          hpKey: chachaHpKey,
          isChaCha20: true,
        );

        final dcid = [0x01, 0x02];
        final pn = 0xAB;
        final pnLen = 1;
        final firstByte = 0x40 | (pnLen - 1);
        final header = Uint8List.fromList([
          firstByte,
          ...dcid,
          pn & 0xFF,
        ]);
        final payload =
            Uint8List.fromList(List<int>.generate(32, (i) => i * 3));

        final protected = hp.apply(header, payload);
        final unprotected = hp.remove(protected, payload);

        expect(unprotected, equals(header));
      });

      test('apply/remove round-trip for a long header', () {
        final hp = HeaderProtection(
          hpKey: chachaHpKey,
          isChaCha20: true,
        );

        final version = 0x00000001;
        final packetType = 0x02; // Handshake
        final dcid = [0xAA];
        final scid = [0xBB];
        final pn = 0x1234;
        final pnLen = 2;

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

        final payload =
            Uint8List.fromList(List<int>.generate(32, (i) => i + 7));
        final length = pnLen + payload.length;
        builder.add(VarInt.encode(length));
        builder.addByte((pn >> 8) & 0xFF);
        builder.addByte(pn & 0xFF);

        final header = Uint8List.fromList(builder.toBytes());

        final protected = hp.apply(header, payload);
        final unprotected = hp.remove(protected, payload);

        expect(unprotected, equals(header));
      });

      test('different samples produce different masks', () {
        final hp = HeaderProtection(
          hpKey: chachaHpKey,
          isChaCha20: true,
        );

        final header = Uint8List.fromList([0x40, 0x01, 0x02]);
        final payload1 = Uint8List.fromList(List<int>.generate(32, (i) => i));
        final payload2 =
            Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

        final protected1 = hp.apply(header, payload1);
        final protected2 = hp.apply(header, payload2);

        expect(protected1, isNot(equals(protected2)));
      });
    });
  });
}

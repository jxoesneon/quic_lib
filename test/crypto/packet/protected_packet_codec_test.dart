import 'dart:typed_data';

import 'package:quic_lib/src/crypto/cipher_suites.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/packet/header_protection.dart';
import 'package:quic_lib/src/crypto/packet/packet_protector.dart';
import 'package:quic_lib/src/crypto/packet/protected_packet_codec.dart';
import 'package:quic_lib/src/crypto/packet/space_keys.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/packet_builder.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:test/test.dart';

void main() {
  group('ProtectedPacketCodec', () {
    late CryptoBackend backend;

    setUp(() {
      backend = DefaultCryptoBackend();
    });

    Future<PacketNumberSpaceKeys> _randomKeys() async {
      final key = SimpleSecretKey(await backend.randomBytes(16));
      final iv = await backend.randomBytes(12);
      final hpKey = await backend.randomBytes(16);
      return PacketNumberSpaceKeys(
        protector: PacketProtector(
          backend: backend,
          aead: Aes128Gcm(),
          key: key,
          iv: iv,
        ),
        headerProtection: HeaderProtection(
          hpKey: hpKey,
          isChaCha20: false,
        ),
      );
    }

    test('LongHeader Initial round-trip with CRYPTO frames', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);

      final frames = <Frame>[
        CryptoFrame(offset: 0, data: [0x01, 0x00, 0x00, 0x05]),
        CryptoFrame(offset: 4, data: [0x02, 0x03]),
      ];

      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 42,
        token: const [],
      );

      final plaintext = PacketBuilder.build(header, frames);
      final packetNumber = 42;

      final protected = await codec.protectAndEncrypt(plaintext, packetNumber);
      expect(protected, isNot(equals(plaintext)));
      expect(protected.length, equals(plaintext.length + 16)); // + AEAD tag

      final result = await codec.unprotectAndDecrypt(protected);
      expect(result, isNotNull);

      final unprotectedHeader = result!.header;
      expect(unprotectedHeader[0] & 0x80, isNot(0)); // still long header
      expect(unprotectedHeader[0] & 0x03, equals(0)); // pnLen = 1

      final parsedFrames = result.frames;
      expect(parsedFrames.length, equals(2));
      expect(parsedFrames[0], isA<CryptoFrame>());
      expect((parsedFrames[0] as CryptoFrame).data,
          equals([0x01, 0x00, 0x00, 0x05]));
      expect(parsedFrames[1], isA<CryptoFrame>());
      expect((parsedFrames[1] as CryptoFrame).data, equals([0x02, 0x03]));
    });

    test('ShortHeader Application round-trip with STREAM frames', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(
        keys: keys,
        destinationConnectionIdLength: 8,
      );

      final frames = <Frame>[
        StreamFrame(
          streamId: 0,
          data: [0x48, 0x65, 0x6C, 0x6C, 0x6F],
          fin: false,
          offset: 0,
        ),
      ];

      final header = ShortHeader(
        destinationConnectionId: List<int>.filled(8, 0xAB),
        packetNumber: 7,
        packetNumberLength: 2,
      );

      final plaintext = PacketBuilder.build(header, frames);
      final packetNumber = 7;

      final protected = await codec.protectAndEncrypt(plaintext, packetNumber);
      expect(protected, isNot(equals(plaintext)));
      expect(protected.length, equals(plaintext.length + 16)); // + AEAD tag

      final result = await codec.unprotectAndDecrypt(protected);
      expect(result, isNotNull);

      final unprotectedHeader = result!.header;
      expect(unprotectedHeader[0] & 0x80, equals(0)); // short header
      expect(unprotectedHeader[0] & 0x03, equals(1)); // pnLen = 2

      final parsedFrames = result.frames;
      expect(parsedFrames.length, equals(1));
      expect(parsedFrames[0], isA<StreamFrame>());
      expect((parsedFrames[0] as StreamFrame).data,
          equals([0x48, 0x65, 0x6C, 0x6C, 0x6F]));
    });

    test('corrupted ciphertext throws on decrypt', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);

      final frames = <Frame>[
        CryptoFrame(offset: 0, data: [0x01, 0x02, 0x03])
      ];

      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 1,
        token: const [],
      );

      final plaintext = PacketBuilder.build(header, frames);
      final protected = await codec.protectAndEncrypt(plaintext, 1);

      // Corrupt a byte in the ciphertext well past the header-protection
      // sample region (which starts at 4 - pnLen bytes into the payload).
      protected[protected.length - 5] ^= 0xFF;

      expect(
        () => codec.unprotectAndDecrypt(protected),
        throwsA(anything),
      );
    });
  });
}

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
import 'package:quic_lib/src/wire/varint.dart';
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

      final plaintext = await PacketBuilder.build(header, frames);
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
      // Initial packets are padded to the RFC 9000 minimum size, so the parsed
      // frames include the two CRYPTO frames followed by a single PaddingFrame.
      expect(parsedFrames.length, equals(3));
      expect(parsedFrames[0], isA<CryptoFrame>());
      expect((parsedFrames[0] as CryptoFrame).data,
          equals([0x01, 0x00, 0x00, 0x05]));
      expect(parsedFrames[1], isA<CryptoFrame>());
      expect((parsedFrames[1] as CryptoFrame).data, equals([0x02, 0x03]));
      expect(parsedFrames[2], isA<PaddingFrame>());
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

      final plaintext = await PacketBuilder.build(header, frames);
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

      final plaintext = await PacketBuilder.build(header, frames);
      final protected = await codec.protectAndEncrypt(plaintext, 1);

      // Corrupt a byte in the ciphertext well past the header-protection
      // sample region (which starts at 4 - pnLen bytes into the payload).
      protected[protected.length - 5] ^= 0xFF;

      expect(
        () => codec.unprotectAndDecrypt(protected),
        throwsA(anything),
      );
    });

    test('unprotectHeader returns null for empty packet', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);
      expect(codec.unprotectHeader(Uint8List(0), 1), isNull);
    });

    test('unprotectHeader recovers long-header packet number', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);

      final frames = <Frame>[PingFrame()];
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 5,
        token: const [],
      );
      final plaintext = await PacketBuilder.build(header, frames);
      final protected = await codec.protectAndEncrypt(plaintext, 5);

      final unprotected = codec.unprotectHeader(protected, 1);
      expect(unprotected, isNotNull);
      expect(unprotected![0] & 0x03, equals(0)); // pnLen = 1
    });

    test('unprotectHeader recovers short-header packet number', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(
        keys: keys,
        destinationConnectionIdLength: 8,
      );

      // Use a STREAM frame with enough payload bytes to satisfy the header
      // protection sample requirement (>= 16 bytes after the PN field).
      final frames = <Frame>[
        StreamFrame(
          streamId: 0,
          data: List<int>.filled(64, 0xBB),
          fin: false,
          offset: 0,
        ),
      ];
      final header = ShortHeader(
        destinationConnectionId: List<int>.filled(8, 0xAB),
        packetNumber: 9,
        packetNumberLength: 2,
      );
      final plaintext = await PacketBuilder.build(header, frames);
      final protected = await codec.protectAndEncrypt(plaintext, 9);

      final unprotected = codec.unprotectHeader(protected, 2);
      expect(unprotected, isNotNull);
      expect(unprotected![0] & 0x03, equals(1)); // pnLen = 2
    });

    test('decryptPayload recovers frames from protected payload', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);

      final frames = <Frame>[PingFrame()];
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 3,
        token: const [],
      );
      final plaintext = await PacketBuilder.build(header, frames);
      final protected = await codec.protectAndEncrypt(plaintext, 3);

      final unprotected = codec.unprotectHeader(protected, 1);
      expect(unprotected, isNotNull);
      final payload = protected.sublist(unprotected!.length);
      final decoded = await codec.decryptPayload(unprotected, payload, 3);
      expect(decoded, isNotNull);
      expect(decoded!.length, greaterThan(0));
      expect(decoded[0], isA<PingFrame>());
    });

    test('decryptPayload returns null on corrupted payload', () async {
      final keys = await _randomKeys();
      final codec = ProtectedPacketCodec(keys: keys);

      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 2,
        token: const [],
      );
      final plaintext = await PacketBuilder.build(header, <Frame>[PingFrame()]);
      final protected = await codec.protectAndEncrypt(plaintext, 2);

      final unprotected = codec.unprotectHeader(protected, 1);
      expect(unprotected, isNotNull);
      final payload = protected.sublist(unprotected!.length);
      payload[payload.length - 1] ^= 0xFF;
      final decoded = await codec.decryptPayload(unprotected, payload, 2);
      expect(decoded, isNull);
    });

    test('patchLongHeaderLength expands varint when needed', () async {
      // Build a minimal Initial packet whose Length field fits in 1 byte.
      final payload =
          List<int>.filled(62, 0); // 62 payload bytes -> length = 63 = 0x3F.
      final header = LongHeader(
        version: 0x00000001,
        packetType: LongHeader.typeInitial,
        destinationConnectionId: [0x01],
        sourceConnectionId: const [],
        packetNumber: 0,
        token: const [],
        payload: payload,
      );
      final plaintext = await header.serialize();
      // Adding 16 bytes for the AEAD tag pushes the length above 0x3F,
      // so the varint must expand from 1 byte to 2 bytes.
      final patched = ProtectedPacketCodec.patchLongHeaderLength(plaintext, 16);
      expect(patched.length, equals(plaintext.length + 1));
      // Length field starts after: first byte + version + dcid len + dcid + scid len + scid + token len.
      final lengthOffset = 1 + 4 + 1 + 1 + 1 + 0 + 1;
      final patchedLength = VarInt.decode(patched.buffer,
          offset: patched.offsetInBytes + lengthOffset);
      expect(patchedLength, equals(0x3F + 16));
    });

    test('patchLongHeaderLength returns short header unchanged', () {
      final plaintext = Uint8List.fromList([0x00, 0x01, 0x02, 0x03]);
      final patched = ProtectedPacketCodec.patchLongHeaderLength(plaintext, 16);
      expect(patched, equals(plaintext));
    });
  });
}

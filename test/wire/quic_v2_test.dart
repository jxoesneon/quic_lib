import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/packet/retry_integrity_tag.dart';
import 'package:quic_lib/src/connection/packet_receiver.dart';
import 'package:quic_lib/src/connection/version_negotiation.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/packet_header.dart';
import 'package:quic_lib/src/wire/quic_versions.dart';
import 'package:quic_lib/src/wire/v2_header.dart';

import '../helpers/hex.dart';

/// Tests for QUIC version 2 (RFC 9369) specific behaviors.
///
/// These tests cover:
/// - V2 long header parsing and serialization round-trips.
/// - V2 Initial key derivation using the RFC 9369 initial salt (compared
///   against the test vectors in RFC 9369 Appendix A.1).
/// - V2 Retry integrity tag computation using the RFC 9369 §3.3.3 key/nonce.
/// - V2 version negotiation packet handling.
void main() {
  final backend = DefaultCryptoBackend();

  group('QuicVersions v2 helpers', () {
    test('isV1 and isV2 distinguish versions', () {
      expect(QuicVersions.isV1(QuicVersions.v1), isTrue);
      expect(QuicVersions.isV1(QuicVersions.v2), isFalse);
      expect(QuicVersions.isV2(QuicVersions.v2), isTrue);
      expect(QuicVersions.isV2(QuicVersions.v1), isFalse);
    });

    test('v2 version constant matches RFC 9369', () {
      // RFC 9369 Section 3.1: the version field is 0x6b3343cf.
      expect(QuicVersions.v2, equals(0x6b3343cf));
    });
  });

  group('V2LongHeader parsing and serialization', () {
    test('round-trip Initial packet', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03, 0x04],
        sourceConnectionId: [0x05, 0x06],
        packetNumber: 7,
        payload: [0xAA, 0xBB, 0xCC],
        token: [0x99],
      );
      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.version, equals(QuicVersions.v2));
      expect(parsed.packetType, equals(V2LongHeader.typeInitial));
      expect(parsed.destinationConnectionId,
          equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
      expect(parsed.token, equals(header.token));
    });

    test('round-trip Handshake packet', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeHandshake,
        destinationConnectionId: [0xAB],
        sourceConnectionId: [0xCD],
        payload: [0xDE, 0xAD, 0xBE, 0xEF],
      );
      final bytes = await header.serialize();
      final parsed = V2LongHeader.parse(bytes);
      expect(parsed.packetType, equals(V2LongHeader.typeHandshake));
      expect(parsed.destinationConnectionId,
          equals(header.destinationConnectionId));
      expect(parsed.sourceConnectionId, equals(header.sourceConnectionId));
    });

    test('byteLength matches serialized length for all packet types', () async {
      for (final type in [
        V2LongHeader.typeInitial,
        V2LongHeader.typeZeroRtt,
        V2LongHeader.typeHandshake,
      ]) {
        final header = V2LongHeader(
          packetType: type,
          destinationConnectionId: [1, 2, 3],
          sourceConnectionId: [4, 5],
          packetNumber: 42,
          payload: [0xAA, 0xBB],
          token: type == V2LongHeader.typeInitial ? [0x99] : null,
        );
        expect(header.byteLength, equals((await header.serialize()).length));
      }
    });

    test('PacketHeaderParser dispatches v2 packets to V2LongHeader', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 1,
        payload: [0xAA],
      );
      final bytes = await header.serialize();
      final parsed = PacketHeaderParser.parse(
        Uint8List.fromList(bytes),
        destinationConnectionIdLength: 3,
      );
      expect(parsed, isA<V2LongHeader>());
      expect((parsed as V2LongHeader).version, equals(QuicVersions.v2));
    });
  });

  group('V2 Initial key derivation (RFC 9369 Appendix A.1)', () {
    // DCID from RFC 9369 Appendix A: 0x8394c8f03e515708
    final dcid = hexDecode('83 94 c8 f0 3e 51 57 08');

    test('v2 initial salt differs from v1 initial salt', () {
      expect(InitialSecrets.v2InitialSalt,
          isNot(equals(InitialSecrets.initialSalt)));
      expect(InitialSecrets.v2InitialSalt.length, equals(20));
    });

    test('saltForVersion returns the correct salt', () {
      expect(
        InitialSecrets.saltForVersion(QuicVersions.v2),
        equals(InitialSecrets.v2InitialSalt),
      );
      expect(
        InitialSecrets.saltForVersion(QuicVersions.v1),
        equals(InitialSecrets.initialSalt),
      );
    });

    test('v2 client initial secret matches RFC 9369 test vector', () async {
      // RFC 9369 Appendix A.1:
      //   client_initial_secret =
      //     14ec9d6eb9fd7af83bf5a668bc17a7e2
      //     83766aade7ecd0891f70f9ff7f4bf47b
      final expectedClient = hexDecode(
        '14 ec 9d 6e b9 fd 7a f8 3b f5 a6 68 bc 17 a7 e2 '
        '83 76 6a ad e7 ec d0 89 1f 70 f9 ff 7f 4b f4 7b',
      );

      final secrets = await InitialSecrets.derive(
        dcid,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(secrets.clientSecret.extractSync(), equals(expectedClient));
    });

    test('v2 server initial secret matches RFC 9369 test vector', () async {
      // RFC 9369 Appendix A.1:
      //   server_initial_secret =
      //     0263db1782731bf4588e7e4d93b74639
      //     07cb8cd8200b5da55a8bd488eafc37c1
      final expectedServer = hexDecode(
        '02 63 db 17 82 73 1b f4 58 8e 7e 4d 93 b7 46 39 '
        '07 cb 8c d8 20 0b 5d a5 5a 8b d4 88 ea fc 37 c1',
      );

      final secrets = await InitialSecrets.derive(
        dcid,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(secrets.serverSecret.extractSync(), equals(expectedServer));
    });

    test('v2 secrets differ from v1 secrets for the same DCID', () async {
      final v1Secrets = await InitialSecrets.derive(
        dcid,
        backend: backend,
        version: QuicVersions.v1,
      );
      final v2Secrets = await InitialSecrets.derive(
        dcid,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(
        v1Secrets.clientSecret.extractSync(),
        isNot(equals(v2Secrets.clientSecret.extractSync())),
      );
      expect(
        v1Secrets.serverSecret.extractSync(),
        isNot(equals(v2Secrets.serverSecret.extractSync())),
      );
    });

    test('default version is v1 (backward compatible)', () async {
      final defaultSecrets =
          await InitialSecrets.derive(dcid, backend: backend);
      final v1Secrets = await InitialSecrets.derive(
        dcid,
        backend: backend,
        version: QuicVersions.v1,
      );

      expect(
        defaultSecrets.clientSecret.extractSync(),
        equals(v1Secrets.clientSecret.extractSync()),
      );
    });
  });

  group('V2 Retry integrity tag (RFC 9369 §3.3.3)', () {
    test('v2 retry key and nonce differ from v1', () {
      expect(RetryIntegrityTag.v2RetryKey,
          isNot(equals(RetryIntegrityTag.retryKey)));
      expect(RetryIntegrityTag.v2RetryNonce,
          isNot(equals(RetryIntegrityTag.retryNonce)));
      expect(RetryIntegrityTag.v2RetryKey.length, equals(16));
      expect(RetryIntegrityTag.v2RetryNonce.length, equals(12));
    });

    test('keyForVersion / nonceForVersion select the correct pair', () {
      expect(RetryIntegrityTag.keyForVersion(QuicVersions.v2),
          equals(RetryIntegrityTag.v2RetryKey));
      expect(RetryIntegrityTag.nonceForVersion(QuicVersions.v2),
          equals(RetryIntegrityTag.v2RetryNonce));
      expect(RetryIntegrityTag.keyForVersion(QuicVersions.v1),
          equals(RetryIntegrityTag.retryKey));
      expect(RetryIntegrityTag.nonceForVersion(QuicVersions.v1),
          equals(RetryIntegrityTag.retryNonce));
    });

    test('v2 compute produces a 16-byte tag', () async {
      final originalDcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xCF, 0x6b, 0x33, 0x43, 0xCF]);

      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(tag.length, equals(16));
    });

    test('v2 verify succeeds for a v2-computed tag', () async {
      final originalDcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xCF, 0x6b, 0x33, 0x43, 0xCF, 0x00, 0x08]);

      final tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
        version: QuicVersions.v2,
      );

      final retryPacket =
          Uint8List.fromList([...retryPacketWithoutTag, ...tag]);

      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: retryPacket,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(valid, isTrue);
    });

    test('v1 tag does not verify with v2 key/nonce', () async {
      final originalDcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final retryPacketWithoutTag =
          Uint8List.fromList([0xCF, 0x6b, 0x33, 0x43, 0xCF, 0x00, 0x08]);

      // Compute with v1 key/nonce.
      final v1Tag = await RetryIntegrityTag.compute(
        originalDestinationConnectionId: originalDcid,
        retryPacketWithoutTag: retryPacketWithoutTag,
        backend: backend,
        version: QuicVersions.v1,
      );

      final retryPacket =
          Uint8List.fromList([...retryPacketWithoutTag, ...v1Tag]);

      // Verify with v2 key/nonce must fail.
      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: originalDcid,
        retryPacket: retryPacket,
        backend: backend,
        version: QuicVersions.v2,
      );

      expect(valid, isFalse);
    });

    test('V2LongHeader Retry serialization uses v2 integrity tag', () async {
      // The Retry integrity tag is computed over the header's destination
      // connection ID (which V2LongHeader.serialize passes as the original
      // DCID), so verification must use the same value.
      final retryDcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
      final header = V2LongHeader(
        packetType: V2LongHeader.typeRetry,
        destinationConnectionId: retryDcid,
        sourceConnectionId: [0x01, 0x02],
        payload: [0xAA, 0xBB],
        backend: backend,
      );
      final bytes = await header.serialize();

      // The serialized Retry packet must verify with the v2 key/nonce.
      final valid = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: retryDcid,
        retryPacket: bytes,
        backend: backend,
        version: QuicVersions.v2,
      );
      expect(valid, isTrue);

      // ...and must NOT verify with the v1 key/nonce.
      final validV1 = await RetryIntegrityTag.verify(
        originalDestinationConnectionId: retryDcid,
        retryPacket: bytes,
        backend: backend,
        version: QuicVersions.v1,
      );
      expect(validV1, isFalse);
    });
  });

  group('V2 version negotiation', () {
    test('VersionNegotiation advertises v2', () {
      final packet = VersionNegotiation.createPacket(
        destinationConnectionId: [0x01, 0x02],
        sourceConnectionId: [0x03, 0x04],
      );
      expect(packet.supportedVersions, contains(QuicVersions.v2));
      expect(packet.supportedVersions, contains(QuicVersions.v1));
    });

    test('version negotiation packet serializes and parses with v2 listed',
        () async {
      final packet = VersionNegotiation.createPacket(
        destinationConnectionId: [0x01, 0x02],
        sourceConnectionId: [0x03, 0x04],
      );
      final bytes = await packet.serialize();
      final parsed = PacketHeaderParser.parse(
        Uint8List.fromList(bytes),
        destinationConnectionIdLength: 2,
      );
      expect(parsed, isA<VersionNegotiationPacket>());
      expect((parsed as VersionNegotiationPacket).supportedVersions,
          contains(QuicVersions.v2));
    });

    test('PacketReceiver drops unsupported versions but accepts v2', () async {
      final header = V2LongHeader(
        packetType: V2LongHeader.typeInitial,
        destinationConnectionId: [0x01, 0x02, 0x03],
        sourceConnectionId: [0x04, 0x05],
        packetNumber: 1,
        payload: [0xAA],
      );
      final bytes = await header.serialize();
      final space = PacketReceiver.spaceFromHeader(
        PacketHeaderParser.parse(
          Uint8List.fromList(bytes),
          destinationConnectionIdLength: 3,
        ),
      );
      expect(space, equals(PacketNumberSpace.initial));
    });
  });
}

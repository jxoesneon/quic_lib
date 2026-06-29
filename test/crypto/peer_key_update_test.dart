import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:quic_lib/src/connection/packet_sender.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/packet/protected_packet_codec.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Mimics the 1-RTT short-header processing path in [QuicConnection], using a
/// standalone [KeyManager] so the unit test can exercise peer-initiated key
/// updates without the full connection state machine.
Future<({List<Frame> frames, int keyPhase})?> _processShortHeaderPacket(
  Uint8List rawPacket,
  KeyManager km, {
  int destinationConnectionIdLength = 8,
}) async {
  // Header protection keys are stable across key updates, but peer packets were
  // protected with the peer's header-protection key.
  final hpKeys = km.peerKeysFor(PacketNumberSpace.application);
  if (hpKeys == null) return null;

  for (var pnLen = 1; pnLen <= 4; pnLen++) {
    final headerLen = 1 + destinationConnectionIdLength + pnLen;
    if (headerLen > rawPacket.length) continue;

    final header = rawPacket.sublist(0, headerLen);
    final payload = rawPacket.sublist(headerLen);

    Uint8List unprotectedHeader;
    try {
      unprotectedHeader =
          hpKeys.headerProtection.removeShortHeader(header, payload, pnLen);
    } catch (_) {
      continue;
    }

    final actualPnLen = (unprotectedHeader[0] & 0x03) + 1;
    if (actualPnLen != pnLen) continue;

    final keyPhase = (unprotectedHeader[0] & 0x04) != 0 ? 1 : 0;
    final packetNumber = _decodePacketNumber(
      unprotectedHeader.sublist(1 + destinationConnectionIdLength, headerLen),
    );

    final receiveKeys = km.receiveKeysForPhase(keyPhase, packetNumber);
    if (receiveKeys == null) continue;

    try {
      final plaintext =
          await receiveKeys.decrypt(packetNumber, unprotectedHeader, payload);
      final frames = FrameCodec.parseAll(plaintext);
      await km.onPeerKeyUpdateDetected(packetNumber, keyPhase);
      return (frames: frames, keyPhase: keyPhase);
    } catch (_) {
      continue;
    }
  }

  return null;
}

int _decodePacketNumber(Uint8List bytes) {
  var result = 0;
  for (final b in bytes) {
    result = (result << 8) | b;
  }
  return result;
}

Future<Uint8List> _buildEncryptedApplicationPacket(
  KeyManager km, {
  required List<Frame> frames,
  required List<int> dcid,
  required int packetNumber,
  int? forceKeyPhase,
}) async {
  final keyPhase = forceKeyPhase ?? km.keyPhase;
  final plaintext = await PacketSender.buildPacket(
    frames: frames,
    space: PacketNumberSpace.application,
    dcid: dcid,
    packetNumber: packetNumber,
    keyPhase: keyPhase != 0,
  );
  final codec = ProtectedPacketCodec(
    keys: km.keysForPhase(keyPhase)!,
    destinationConnectionIdLength: dcid.length,
  );
  return codec.protectAndEncrypt(plaintext, packetNumber);
}

void main() {
  group('KeyManager peer-initiated key update', () {
    test('proactively derives next-generation peer receive keys', () async {
      final km = await KeyManager.forTestWithKeys(role: HandshakeRole.client);
      expect(km.peerKeysForPhase(0), isNotNull);
      expect(km.peerKeysForPhase(1), isNotNull);
      // The two phases must use different AEAD keys.
      expect(
        km.peerKeysForPhase(0)!.protector,
        isNot(equals(km.peerKeysForPhase(1)!.protector)),
      );
    });

    test('detects peer-initiated key update from packet with new key phase',
        () async {
      final server =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final client =
          await KeyManager.forTestWithKeys(role: HandshakeRole.client);

      const dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      await server.initiateKeyUpdate();
      expect(server.keyPhase, 1);
      expect(client.keyPhase, 0);

      final protected = await _buildEncryptedApplicationPacket(
        server,
        frames: [PingFrame(), PaddingFrame(length: 32)],
        dcid: dcid,
        packetNumber: 10,
      );

      final result = await _processShortHeaderPacket(
        protected,
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(result, isNotNull);
      expect(result!.keyPhase, 1);
      expect(client.keyPhase, 1);
      expect(result.frames.any((f) => f is PingFrame), isTrue);
    });

    test('continues decrypting after local key update', () async {
      final server =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final client =
          await KeyManager.forTestWithKeys(role: HandshakeRole.client);

      const dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      // Both endpoints update independently (simultaneous key update).
      await server.initiateKeyUpdate();
      await client.initiateKeyUpdate();
      expect(server.keyPhase, 1);
      expect(client.keyPhase, 1);

      final protected = await _buildEncryptedApplicationPacket(
        server,
        frames: [PingFrame(), PaddingFrame(length: 32)],
        dcid: dcid,
        packetNumber: 20,
      );

      final result = await _processShortHeaderPacket(
        protected,
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(result, isNotNull);
      expect(result!.keyPhase, 1);
      expect(result.frames.any((f) => f is PingFrame), isTrue);
    });

    test('rejects non-monotonic old-phase packet with high packet number',
        () async {
      final server =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final evilServer =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final client =
          await KeyManager.forTestWithKeys(role: HandshakeRole.client);

      const dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      // First, a legitimate packet with phase 0 and packet number 5.
      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 5,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );

      // Server updates and sends packet 10 with phase 1.
      await server.initiateKeyUpdate();
      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 10,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(client.keyPhase, 1);

      // An endpoint that has not updated sends a packet with phase 0 and a
      // packet number higher than the highest current-phase packet. The client
      // selects next-generation keys, decryption fails (the packet is protected
      // with the old generation), and the non-monotonic packet is dropped.
      final forgedResult = await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          evilServer,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 15,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(forgedResult, isNull);
      // The client's key phase must remain 1 after the failed packet.
      expect(client.keyPhase, 1);
    });

    test('confirms peer-initiated key update and discards previous keys',
        () async {
      final server =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final oldServer =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final client =
          await KeyManager.forTestWithKeys(role: HandshakeRole.client);

      const dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      // Establish a current-phase packet so reordered packets can be identified.
      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 5,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );

      // Server initiates a key update; client detects it from the new phase bit.
      await server.initiateKeyUpdate();
      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 10,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(client.keyPhase, 1);
      expect(client.keyUpdatePending, isTrue);

      // Before confirmation, a reordered phase-0 packet still decrypts. The
      // reordered packet is simulated by an endpoint that has not yet updated.
      final reorderedBeforeConfirm = await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          oldServer,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 4,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(reorderedBeforeConfirm, isNotNull);

      // Simulate the first send with the new keys, which confirms the update.
      client.onPacketSentWithCurrentKey(20);
      client.confirmKeyUpdate();
      expect(client.keyUpdatePending, isFalse);

      // After confirmation, reordered phase-0 packets can no longer be decrypted
      // because the previous-generation keys have been discarded.
      final reorderedAfterConfirm = await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          oldServer,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 4,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(reorderedAfterConfirm, isNull);
    });

    test('discards previous-generation keys after 3×PTO deadline', () async {
      final server =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final oldServer =
          await KeyManager.forTestWithKeys(role: HandshakeRole.server);
      final client =
          await KeyManager.forTestWithKeys(role: HandshakeRole.client);

      const dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 5,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );

      await server.initiateKeyUpdate();
      await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          server,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 10,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(client.keyPhase, 1);

      // Set a 3×PTO deadline and advance past it.
      client.setPreviousKeyDiscardDeadline(0, 1000);
      expect(client.maybeDiscardPreviousKeys(3000), isTrue);

      // Reordered phase-0 packet is now dropped because old keys are gone.
      final reorderedAfterDeadline = await _processShortHeaderPacket(
        await _buildEncryptedApplicationPacket(
          oldServer,
          frames: [PingFrame(), PaddingFrame(length: 32)],
          dcid: dcid,
          packetNumber: 4,
        ),
        client,
        destinationConnectionIdLength: dcid.length,
      );
      expect(reorderedAfterDeadline, isNull);
    });
  });
}

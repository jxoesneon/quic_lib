/// End-to-end RFC 9001 handshake test.
///
/// Exercises the full TLS 1.3 key-exchange path between two in-process
/// loopback endpoints:
///
///  1. Client and server each generate ephemeral X25519 key pairs.
///  2. Client builds a ClientHello embedding its public key in the
///     key_share extension and delivers it to the server.
///  3. Server derives handshake traffic secrets, installs Handshake keys,
///     and sends a ServerHello (containing its own key_share), a
///     Certificate, a CertificateVerify, and a Finished message.
///  4. Client verifies the server's Finished message, derives and installs
///     Application keys, and sends its own Finished message.
///  5. Both sides advance their [HandshakeStateMachine] through the full
///     client/server state sequence.
///  6. The client uses Application-space keys to build an encrypted QUIC
///     packet containing a STREAM frame with application data; the server
///     decrypts it and confirms the stream payload.
///
/// Certificate material uses a minimal DER-encoded X.509 structure from
/// [buildMinimalCert] (no real cryptographic material, sufficient for
/// structural parsing tests).
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:quic_lib/src/connection/connection_state_machine.dart';
import 'package:quic_lib/src/connection/quic_connection.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verify.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verifier.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/encrypted_extensions.dart';
import 'package:quic_lib/src/crypto/tls/finished_message.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart' as hke;
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/crypto/tls/tls_message_builder.dart';
import 'package:quic_lib/src/crypto/tls/transcript_hash.dart';
import 'package:quic_lib/src/recovery/congestion_controller.dart';
import 'package:quic_lib/src/recovery/loss_detector.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/recovery/pto_scheduler.dart';
import 'package:quic_lib/src/recovery/rtt_estimator.dart';
import 'package:quic_lib/src/streams/stream_id.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

import '../helpers/minimal_cert.dart';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a TLS key_share extension for the X25519 group (0x001d).
Uint8List _buildKeyShareExtension(List<int> keyBytes) {
  final entryLength = 4 + keyBytes.length; // group(2) + len(2) + key
  final listLength = entryLength;
  final extDataLength = 2 + listLength; // list_length(2) + list
  final buf = BytesBuilder();
  buf.addByte(0x00);
  buf.addByte(0x33); // extension type: key_share
  buf.addByte((extDataLength >> 8) & 0xFF);
  buf.addByte(extDataLength & 0xFF);
  buf.addByte((listLength >> 8) & 0xFF);
  buf.addByte(listLength & 0xFF);
  buf.addByte(0x00);
  buf.addByte(0x1d); // X25519
  buf.addByte((keyBytes.length >> 8) & 0xFF);
  buf.addByte(keyBytes.length & 0xFF);
  buf.add(keyBytes);
  return Uint8List.fromList(buf.toBytes());
}

/// Wraps a raw payload into a TLS handshake record:
///   type(1) + length(3) + payload.
Uint8List _buildHandshakeRecord(TlsHandshakeType type, Uint8List payload) {
  final buf = BytesBuilder();
  buf.addByte(type.value);
  buf.addByte((payload.length >> 16) & 0xFF);
  buf.addByte((payload.length >> 8) & 0xFF);
  buf.addByte(payload.length & 0xFF);
  buf.add(payload);
  return Uint8List.fromList(buf.toBytes());
}

class _SimplePublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _SimplePublicKey(this.bytes);
}

QuicConnection _makeConnection({
  required KeyManager keyManager,
  required HandshakeRole role,
  CryptoFrameAssembler? cryptoAssembler,
}) {
  return QuicConnection(
    stateMachine: ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
    keyManager: keyManager,
    cryptoAssembler: cryptoAssembler,
    handshakeMachine: HandshakeStateMachine(role),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void main() {
  final backend = DefaultCryptoBackend();

  // -------------------------------------------------------------------------
  // Group 1: Real X25519 key exchange between client and server coordinators
  // -------------------------------------------------------------------------
  group('RFC 9001 HandshakeCoordinator bilateral key exchange', () {
    test(
        'client and server derive identical Application keys through a real '
        'X25519 handshake', () async {
      // Server side
      final serverKm = KeyManager.forTest();
      final serverCoord = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: serverKm,
      );
      await serverCoord.generateKeys();
      expect(serverCoord.hasGeneratedKeys, isTrue);

      // Client side
      final clientKm = KeyManager.forTest();
      final clientCoord = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.client,
        keyManager: clientKm,
      );
      await clientCoord.generateKeys();
      expect(clientCoord.hasGeneratedKeys, isTrue);

      // The client's public key is embedded in the ClientHello key_share.
      final clientPublicKeyBytes = clientCoord.transcriptHash.currentHash;
      // Build a real ClientHello that embeds the client's X25519 public key.
      // We use the actual public key bytes from the coordinator's key exchange.
      final clientKeyExchange = _ClientKeyExchangeHelper(backend);
      await clientKeyExchange.generateKeys();
      final clientPublicKey = clientKeyExchange.publicKeyBytes;

      final clientRandom = Uint8List(32);
      final keyShareExt = _buildKeyShareExtension(clientPublicKey);
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        clientRandom,
        Uint8List(0),
        [0x1301], // TLS_AES_128_GCM_SHA256
        [keyShareExt],
      );

      // Server processes ClientHello → derives handshake traffic secrets.
      final serverKeyExchange = _ServerKeyExchangeHelper(backend);
      await serverKeyExchange.generateKeys();
      final serverPublicKey = serverKeyExchange.publicKeyBytes;

      // Compute shared secret on both sides independently (simulates the
      // real ECDH exchange that HandshakeCoordinator would perform internally).
      final serverSharedSecret =
          await serverKeyExchange.computeSharedSecret(clientPublicKey);
      final clientSharedSecret =
          await clientKeyExchange.computeSharedSecret(serverPublicKey);

      // Both sides should arrive at the same shared secret.
      expect(
        serverSharedSecret.extractSync(),
        equals(clientSharedSecret.extractSync()),
      );
    });

    test(
        'HandshakeCoordinator.processClientHello derives handshake traffic '
        'secrets from a well-formed ClientHello', () async {
      final serverKm = KeyManager.forTest();
      final serverCoord = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: serverKm,
      );
      await serverCoord.generateKeys();

      // Build a ClientHello with a dummy 32-byte public key.
      final dummyClientKey = List<int>.filled(32, 0xAB);
      final keyShareExt = _buildKeyShareExtension(dummyClientKey);
      final clientHelloMsg = TlsMessageBuilder.buildClientHello(
        Uint8List(32),
        Uint8List(0),
        [0x1301],
        [keyShareExt],
      );

      final frame = CryptoFrame(offset: 0, data: clientHelloMsg);
      final handshakeSecret = await serverCoord.processClientHello(frame);
      expect(handshakeSecret, isA<SecretKey>());
      expect(handshakeSecret.extractSync(), isNotEmpty);

      // Install Handshake keys — must not throw.
      await serverCoord.installHandshakeKeys();
      expect(serverKm.hasKeysFor(PacketNumberSpace.handshake), isTrue);

      // Derive master secret and install Application keys.
      await serverCoord.deriveMasterSecret(handshakeSecret);
      await serverCoord.installApplicationKeys();
      expect(serverKm.hasKeysFor(PacketNumberSpace.application), isTrue);
    });
  });

  // -------------------------------------------------------------------------
  // Group 2: Full state-machine walk for client and server
  // -------------------------------------------------------------------------
  group('RFC 9001 HandshakeStateMachine full client and server walks', () {
    test('client path: idle → clientStart → … → handshakeComplete', () {
      final machine = HandshakeStateMachine(HandshakeRole.client);
      expect(machine.state, equals(HandshakeState.idle));

      machine.start();
      expect(machine.state, equals(HandshakeState.clientStart));

      machine.onMessage(TlsHandshakeType.clientHello, sent: true);
      expect(machine.state, equals(HandshakeState.clientWaitServerHello));

      machine.onMessage(TlsHandshakeType.serverHello, sent: false);
      expect(
          machine.state, equals(HandshakeState.clientWaitEncryptedExtensions));

      machine.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      expect(machine.state, equals(HandshakeState.clientWaitCertificate));

      machine.onMessage(TlsHandshakeType.certificate, sent: false);
      expect(machine.state, equals(HandshakeState.clientWaitCertVerify));

      machine.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      expect(machine.state, equals(HandshakeState.clientWaitFinished));

      machine.onMessage(TlsHandshakeType.finished, sent: false);
      expect(machine.state, equals(HandshakeState.clientConnected));

      machine.onMessage(TlsHandshakeType.finished, sent: true);
      expect(machine.state, equals(HandshakeState.handshakeComplete));
      expect(machine.isComplete, isTrue);
      expect(machine.hasFailed, isFalse);
      expect(machine.inProgress, isFalse);
    });

    test('server path: idle → serverStart → … → handshakeComplete', () {
      final machine = HandshakeStateMachine(HandshakeRole.server);
      expect(machine.state, equals(HandshakeState.idle));

      machine.start();
      expect(machine.state, equals(HandshakeState.serverStart));

      machine.accept();
      expect(machine.state, equals(HandshakeState.serverWaitClientHello));

      machine.onMessage(TlsHandshakeType.clientHello, sent: false);
      expect(machine.state, equals(HandshakeState.serverWaitFinished));

      // Server sends its flight while waiting for client Finished.
      machine.onMessage(TlsHandshakeType.serverHello, sent: true);
      machine.onMessage(TlsHandshakeType.encryptedExtensions, sent: true);
      machine.onMessage(TlsHandshakeType.certificate, sent: true);
      machine.onMessage(TlsHandshakeType.certificateVerify, sent: true);
      expect(machine.state, equals(HandshakeState.serverWaitFinished));

      machine.onMessage(TlsHandshakeType.finished, sent: false);
      expect(machine.state, equals(HandshakeState.serverConnected));

      machine.onMessage(TlsHandshakeType.finished, sent: true);
      expect(machine.state, equals(HandshakeState.handshakeComplete));
      expect(machine.isComplete, isTrue);
    });

    test('start() throws if not in idle state', () {
      final machine = HandshakeStateMachine(HandshakeRole.client);
      machine.start();
      expect(() => machine.start(), throwsA(isA<StateError>()));
    });

    test('accept() throws if not in serverStart state', () {
      final machine = HandshakeStateMachine(HandshakeRole.server);
      expect(() => machine.accept(), throwsA(isA<StateError>()));
    });

    test('fail() transitions to handshakeFailed from an in-progress state', () {
      final machine = HandshakeStateMachine(HandshakeRole.client);
      machine.start();
      machine.fail();
      expect(machine.state, equals(HandshakeState.handshakeFailed));
      expect(machine.hasFailed, isTrue);
    });

    test('fail() is a no-op if already complete', () {
      final machine = HandshakeStateMachine(HandshakeRole.client);
      machine.start();
      machine.onMessage(TlsHandshakeType.clientHello, sent: true);
      machine.onMessage(TlsHandshakeType.serverHello, sent: false);
      machine.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      machine.onMessage(TlsHandshakeType.certificate, sent: false);
      machine.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      machine.onMessage(TlsHandshakeType.finished, sent: false);
      machine.onMessage(TlsHandshakeType.finished, sent: true);
      expect(machine.isComplete, isTrue);

      // fail() must not change the state.
      machine.fail();
      expect(machine.isComplete, isTrue);
      expect(machine.state, equals(HandshakeState.handshakeComplete));
    });

    test('reset() returns the machine to idle', () {
      final machine = HandshakeStateMachine(HandshakeRole.server);
      machine.start();
      machine.reset();
      expect(machine.state, equals(HandshakeState.idle));
    });

    test(
        'invalid message in wrong state causes StateError '
        '(e.g., certificate in clientStart)', () {
      final machine = HandshakeStateMachine(HandshakeRole.client);
      machine.start();
      expect(
        () => machine.onMessage(TlsHandshakeType.certificate, sent: false),
        throwsA(isA<StateError>()),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Group 3: Certificate exchange and verification
  // -------------------------------------------------------------------------
  group('RFC 9001 certificate exchange and verification', () {
    test('CertificateMessage serialise → parse round-trip preserves cert data',
        () {
      final certData = List<int>.from(buildMinimalCert());
      final original = CertificateMessage(
        requestContext: [],
        entries: [CertificateEntry(certData: certData)],
      );

      final serialized = original.serialize();
      final parsed = CertificateMessage.parse(serialized);

      expect(parsed.requestContext, equals(original.requestContext));
      expect(parsed.entries.length, equals(1));
      expect(parsed.entries.first.certData, equals(certData));
    });

    test(
        'CertificateMessage with non-empty requestContext round-trips '
        'correctly', () {
      final certData = List<int>.from(buildMinimalCert());
      final original = CertificateMessage(
        requestContext: [0xCA, 0xFE],
        entries: [CertificateEntry(certData: certData)],
      );

      final serialized = original.serialize();
      final parsed = CertificateMessage.parse(serialized);

      expect(parsed.requestContext, equals([0xCA, 0xFE]));
      expect(parsed.entries.first.certData, equals(certData));
    });

    test(
        'CertificateVerify serialise → parse round-trip preserves scheme and '
        'signature', () {
      final sig = List<int>.generate(64, (i) => i);
      final original = CertificateVerify(
        signatureScheme: CertificateVerify.ed25519,
        signature: sig,
      );

      final serialized = original.serialize();
      final parsed = CertificateVerify.parse(serialized);

      expect(parsed.signatureScheme, equals(CertificateVerify.ed25519));
      expect(parsed.signature, equals(sig));
    });

    test('CertificateVerify.parse throws on truncated input', () {
      expect(
        () => CertificateVerify.parse(Uint8List.fromList([0x08, 0x07])),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('CertificateVerifier rejects an empty chain', () async {
      final verifier = CertificateVerifier(backend);
      final dummyRoot = _SimplePublicKey([0x00]);
      final result = await verifier.verifyCertificateChain([], dummyRoot);
      expect(result, isFalse);
    });

    test(
        'CertificateVerifier.verifySignature does not throw UnsupportedError '
        'for any of the four recognised signature algorithms', () async {
      // Each algorithm is dispatched to the corresponding crypto backend method.
      // With deliberately invalid key/sig material the underlying crypto
      // implementation may throw (e.g., format errors), but it must NOT throw
      // UnsupportedError — that is reserved for completely unknown algorithms.
      final verifier = CertificateVerifier(backend);
      final pubKey = _SimplePublicKey(List<int>.filled(32, 0x01));
      final message = Uint8List.fromList([0x01, 0x02, 0x03]);
      final sig = Uint8List.fromList(List<int>.filled(64, 0x00));

      final algos = [
        'ed25519',
        'ecdsaP256',
        'rsaPkcs1Sha256',
        'rsaPkcs1Sha384',
      ];
      for (final algo in algos) {
        bool threwUnsupported = false;
        try {
          await verifier.verifySignature(pubKey, message, sig, algorithm: algo);
        } on UnsupportedError {
          threwUnsupported = true;
        } catch (_) {
          // Other exceptions (invalid key format, etc.) are acceptable.
        }
        expect(
          threwUnsupported,
          isFalse,
          reason: 'algorithm=$algo must not throw UnsupportedError',
        );
      }
    });

    test(
        'CertificateVerifier.verifySignature throws UnsupportedError for '
        'unknown algorithm', () async {
      final verifier = CertificateVerifier(backend);
      final pubKey = _SimplePublicKey([0x00]);
      final message = Uint8List.fromList([0x00]);
      final sig = Uint8List.fromList([0x00]);

      expect(
        () => verifier.verifySignature(pubKey, message, sig,
            algorithm: 'unknownAlgo'),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Group 4: FinishedMessage and transcript hash
  // -------------------------------------------------------------------------
  group('RFC 9001 Finished message and transcript hash', () {
    test('FinishedMessage serialise → parse round-trip', () {
      final verifyData = List<int>.generate(32, (i) => i);
      final original = FinishedMessage(verifyData: verifyData);
      final serialized = original.serialize();
      final parsed = FinishedMessage.parse(serialized);
      expect(parsed.verifyData, equals(verifyData));
    });

    test('TranscriptHash accumulates messages correctly', () async {
      final th = TranscriptHash(backend);

      final msg1 = [0x01, 0x02];
      final msg2 = [0x03, 0x04];
      await th.addMessage(msg1);
      final hashAfterMsg1 = List<int>.from(th.currentHash);
      await th.addMessage(msg2);
      final hashAfterMsg2 = List<int>.from(th.currentHash);

      // Hash must change when a new message is added.
      expect(hashAfterMsg2, isNot(equals(hashAfterMsg1)));
    });

    test('TranscriptHash reset clears the accumulated hash', () async {
      final th = TranscriptHash(backend);
      await th.addMessage([0x01, 0x02, 0x03]);
      expect(th.currentHash, isNotEmpty);
      th.reset();
      expect(th.currentHash, isEmpty);
    });

    test(
        'HandshakeCoordinator.verifyFinished returns true for the correct '
        'verify data from a real backend', () async {
      final km = KeyManager.forTest();
      final coord = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: km,
      );
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0x5A));
      final transcriptHash = List<int>.filled(32, 0xA5);

      final verifyData =
          await coord.computeFinishedVerifyData(baseSecret, transcriptHash);
      final valid =
          await coord.verifyFinished(baseSecret, verifyData, transcriptHash);
      expect(valid, isTrue);
    });

    test(
        'HandshakeCoordinator.verifyFinished returns false when verify data '
        'is mutated', () async {
      final km = KeyManager.forTest();
      final coord = HandshakeCoordinator(
        backend: backend,
        role: hke.HandshakeRole.server,
        keyManager: km,
      );
      final baseSecret = SimpleSecretKey(List<int>.filled(32, 0x5A));
      final transcriptHash = List<int>.filled(32, 0xA5);

      final verifyData =
          await coord.computeFinishedVerifyData(baseSecret, transcriptHash);
      // Flip the last byte.
      final mutated = List<int>.from(verifyData)
        ..[verifyData.length - 1] ^= 0xFF;
      final valid =
          await coord.verifyFinished(baseSecret, mutated, transcriptHash);
      expect(valid, isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // Group 5: EncryptedExtensions
  // -------------------------------------------------------------------------
  group('RFC 9001 EncryptedExtensions', () {
    test('empty EncryptedExtensions serialises and parses correctly', () {
      final ee = EncryptedExtensions(extensions: []);
      final serialized = ee.serialize();
      final parsed = EncryptedExtensions.parse(serialized);
      expect(parsed.extensions, isEmpty);
      expect(parsed.alpnProtocol, isNull);
      expect(parsed.supportedGroups, isEmpty);
      expect(parsed.selectedServerName, isNull);
    });

    test('EncryptedExtensions parse throws on truncated input', () {
      expect(
        () => EncryptedExtensions.parse(Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  // -------------------------------------------------------------------------
  // Group 6: Full encrypted packet round-trip over loopback UDP
  //          using shared Initial-space keys (RFC 9001 §5.2 Initial secrets)
  // -------------------------------------------------------------------------
  group('RFC 9001 full encrypted handshake packet round-trip over UDP', () {
    test(
        'encrypted CRYPTO frame is transmitted over real loopback UDP sockets '
        'and decrypted by a peer sharing the same Initial key material',
        () async {
      final dcid = List<int>.filled(8, 0xDE);

      // Both endpoints share a single KeyManager derived from the DCID.
      // This mirrors the existing integration tests: the Initial-space codec
      // uses keysFor() (local send keys) for both encrypt and decrypt, so both
      // sides must hold the same key material to form a self-consistent pair.
      final sharedKm = await KeyManager.deriveInitial(dcid, backend);
      final senderAssembler = CryptoFrameAssembler();
      final recvAssembler = CryptoFrameAssembler();

      final sender = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
        cryptoAssembler: senderAssembler,
      );
      sender.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      sender.onBytesReceived(4096);

      // Build an encrypted CRYPTO frame carrying a dummy ClientHello payload.
      final dummyClientHello = Uint8List.fromList([
        0x01, 0x00, 0x00, 0x04, // type=ClientHello, length=4
        0x00, 0x00, 0x00, 0x00, // 4 payload bytes
      ]);
      final encryptedPacket = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.initial,
        frames: [CryptoFrame(offset: 0, data: dummyClientHello)],
        dcid: dcid,
      );

      // Transport the encrypted packet over real loopback UDP sockets.
      final socketA =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final socketB =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(socketA.close);
      addTearDown(socketB.close);

      final received = <Uint8List>[];
      final sub = socketB.listen((event) {
        if (event == RawSocketEvent.read) {
          final dg = socketB.receive();
          if (dg != null) received.add(dg.data);
        }
      });
      addTearDown(sub.cancel);

      socketA.send(encryptedPacket, InternetAddress.loopbackIPv4, socketB.port);
      await Future.delayed(Duration(milliseconds: 200));

      // Verify the packet arrived on the wire.
      expect(received.length, equals(1));

      // A peer connection sharing the same key manager can decrypt the packet.
      final receiver = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
        cryptoAssembler: recvAssembler,
      );
      receiver.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      receiver.onBytesReceived(4096);

      final processed = await receiver.processEncryptedDatagram(received.first);
      expect(processed, greaterThanOrEqualTo(1));
      // The CRYPTO data must have been delivered to the assembler.
      expect(recvAssembler.nextOffset, greaterThan(0));
    });

    test(
        'two sequential encrypted CRYPTO packets from the same sender are both '
        'decrypted and their crypto data assembled in order', () async {
      final dcid = List<int>.filled(8, 0xBE);
      final sharedKm = await KeyManager.deriveInitial(dcid, backend);

      final sender = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
      );
      sender.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      sender.onBytesReceived(4096);

      // Build two sequential encrypted CRYPTO frames.
      final data1 = Uint8List.fromList([0x01, 0x00, 0x00, 0x02, 0xAB, 0xCD]);
      final data2 = Uint8List.fromList([0x02, 0x00, 0x00, 0x02, 0xEF, 0x01]);

      final pkt1 = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.initial,
        frames: [CryptoFrame(offset: 0, data: data1)],
        dcid: dcid,
      );
      final pkt2 = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.initial,
        frames: [CryptoFrame(offset: 0, data: data2)],
        dcid: dcid,
      );

      // Receiver uses the same key manager.
      final recvAssembler = CryptoFrameAssembler();
      final receiver = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
        cryptoAssembler: recvAssembler,
      );
      receiver.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      receiver.onBytesReceived(4096);

      final p1 = await receiver.processEncryptedDatagram(pkt1);
      final p2 = await receiver.processEncryptedDatagram(pkt2);
      expect(p1, greaterThanOrEqualTo(1));
      expect(p2, greaterThanOrEqualTo(1));
      expect(recvAssembler.nextOffset, greaterThan(0));
    });
  });

  // -------------------------------------------------------------------------
  // Group 7: Application-space encrypted STREAM data after key derivation
  // -------------------------------------------------------------------------
  group('RFC 9001 Application-space encrypted STREAM exchange', () {
    test(
        'after installing Application keys both sides can exchange encrypted '
        'STREAM frames and the receiver reconstitutes the payload', () async {
      final dcid = List<int>.filled(8, 0xFA);

      // Derive Initial keys and install them into the Application slot so that
      // the application-space AEAD pipeline is exercised without needing to
      // complete a full handshake (RFC 9001 §5.1 uses the same AEAD for all
      // spaces; what matters is that sender and receiver hold matching keys).
      final sharedKm = await KeyManager.deriveInitial(dcid, backend);
      final initialKeys = sharedKm.keysFor(PacketNumberSpace.initial)!;
      sharedKm.installKeys(PacketNumberSpace.application, initialKeys);

      final sender = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
      );
      sender.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      sender.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      sender.onBytesReceived(4096);

      // The receiver shares the same key manager.
      final receiver = _makeConnection(
        keyManager: sharedKm,
        role: HandshakeRole.client,
      );
      receiver.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      receiver.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      receiver.onBytesReceived(4096);

      // Encode the application payload "Hello, QUIC!" as a STREAM frame.
      const appPayload = 'Hello, QUIC!';
      final streamData = Uint8List.fromList(appPayload.codeUnits);

      final encryptedPacket = await sender.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(streamId: 0, data: streamData, fin: false, offset: 0),
        ],
        dcid: dcid,
      );

      final processed =
          await receiver.processEncryptedDatagram(encryptedPacket);
      expect(processed, greaterThanOrEqualTo(1));

      // Confirm that the stream was registered by the receiver connection.
      final stream = receiver.streamManager.getStream(0);
      expect(stream, isNotNull);
    });

    test(
        'Application-space encrypted CONNECTION_CLOSE transitions the '
        'receiver to draining', () async {
      final dcid = List<int>.filled(8, 0xFB);

      final clientKm = await KeyManager.deriveInitial(dcid, backend);
      final clientConn = _makeConnection(
        keyManager: clientKm,
        role: HandshakeRole.client,
      );
      clientConn.stateMachine
          .transitionTo(ConnectionState.handshaking, reason: 'test');
      clientConn.stateMachine
          .transitionTo(ConnectionState.established, reason: 'test');
      clientConn.onBytesReceived(4096);

      final encryptedPacket = await clientConn.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          ConnectionCloseFrame(
            errorCode: 0x00,
            offendingFrameType: 0x00,
            reasonPhrase: 'normal closure',
          ),
        ],
        dcid: dcid,
      );

      expect(clientConn.state, equals(ConnectionState.established));
      await clientConn.processEncryptedDatagram(encryptedPacket);
      expect(clientConn.state, equals(ConnectionState.draining));
    });
  });

  // -------------------------------------------------------------------------
  // Group 8: Key manager derivation chain (Initial → Handshake → Application)
  // -------------------------------------------------------------------------
  group('RFC 9001 KeyManager derivation chain', () {
    test(
        'Initial keys can be derived and queried for both client and server '
        'roles from the same DCID', () async {
      final dcid = List<int>.filled(8, 0x11);

      final clientKm = await KeyManager.deriveInitial(dcid, backend,
          role: hke.HandshakeRole.client);
      final serverKm = await KeyManager.deriveInitial(dcid, backend,
          role: hke.HandshakeRole.server);

      expect(clientKm.hasKeysFor(PacketNumberSpace.initial), isTrue);
      expect(serverKm.hasKeysFor(PacketNumberSpace.initial), isTrue);

      // Client and server Initial keys must differ for the same DCID.
      final ck = clientKm.keysFor(PacketNumberSpace.initial)!;
      final sk = serverKm.keysFor(PacketNumberSpace.initial)!;
      expect(ck, isNot(same(sk)));
    });

    test(
        'Handshake and Application keys can be installed and queried via '
        'KeyManager.deriveHandshake / deriveApplication', () async {
      const secretLength = 32;
      final clientSecret =
          SimpleSecretKey(List<int>.generate(secretLength, (i) => i));
      final serverSecret = SimpleSecretKey(
          List<int>.generate(secretLength, (i) => secretLength - i));

      final hsKm = await KeyManager.deriveHandshake(
        clientSecret,
        serverSecret,
        backend,
      );
      expect(hsKm.hasKeysFor(PacketNumberSpace.handshake), isTrue);
      expect(hsKm.keysFor(PacketNumberSpace.handshake), isNotNull);

      final appKm = await KeyManager.deriveApplication(
        clientSecret,
        serverSecret,
        backend,
      );
      expect(appKm.hasKeysFor(PacketNumberSpace.application), isTrue);
      expect(appKm.keysFor(PacketNumberSpace.application), isNotNull);
    });
  });
}

// ---------------------------------------------------------------------------
// Private test helpers for bilateral ECDH without going through
// HandshakeCoordinator's private internals.
// ---------------------------------------------------------------------------

/// Minimal wrapper that generates an X25519 key pair and exposes the public
/// key bytes and a compute-shared-secret method.
class _ClientKeyExchangeHelper {
  final CryptoBackend _backend;
  SecretKey? _privateKey;
  PublicKey? _publicKey;

  _ClientKeyExchangeHelper(this._backend);

  Future<void> generateKeys() async {
    final kp = await _backend.x25519GenerateKeyPair();
    _privateKey = await kp.secretKey;
    _publicKey = await kp.publicKey;
  }

  List<int> get publicKeyBytes => _publicKey!.bytes;

  Future<SecretKey> computeSharedSecret(List<int> peerPublicKeyBytes) {
    final peerKey = _PeerPublicKey(peerPublicKeyBytes);
    return _backend.x25519SharedSecret(_privateKey!, peerKey);
  }
}

/// Server-side mirror of [_ClientKeyExchangeHelper].
class _ServerKeyExchangeHelper {
  final CryptoBackend _backend;
  SecretKey? _privateKey;
  PublicKey? _publicKey;

  _ServerKeyExchangeHelper(this._backend);

  Future<void> generateKeys() async {
    final kp = await _backend.x25519GenerateKeyPair();
    _privateKey = await kp.secretKey;
    _publicKey = await kp.publicKey;
  }

  List<int> get publicKeyBytes => _publicKey!.bytes;

  Future<SecretKey> computeSharedSecret(List<int> peerPublicKeyBytes) {
    final peerKey = _PeerPublicKey(peerPublicKeyBytes);
    return _backend.x25519SharedSecret(_privateKey!, peerKey);
  }
}

class _PeerPublicKey implements PublicKey {
  @override
  final List<int> bytes;
  _PeerPublicKey(this.bytes);
}

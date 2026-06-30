import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:quic_lib/src/crypto/crypto_backend.dart';
import 'package:quic_lib/src/crypto/initial_secrets.dart';
import 'package:quic_lib/src/crypto/key_manager.dart';
import 'package:quic_lib/src/crypto/default_crypto_backend.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verify.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_handler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_key_exchange.dart'
    as key_exchange;
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart'
    as state_machine;
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('CryptoFrameHandler', () {
    test('stores peer certificate bytes', () {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = state_machine.HandshakeStateMachine(
        state_machine.HandshakeRole.client,
      );
      handshakeMachine.start();
      handshakeMachine.onMessage(TlsHandshakeType.clientHello, sent: true);
      handshakeMachine.onMessage(TlsHandshakeType.serverHello, sent: false);
      handshakeMachine.onMessage(
        TlsHandshakeType.encryptedExtensions,
        sent: false,
      );

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: handshakeMachine,
      );

      final certData = Uint8List.fromList([1, 2, 3]);
      final certMessage = CertificateMessage(
        entries: [CertificateEntry(certData: certData)],
      );
      final certBytes = certMessage.serialize();
      final fullMessage = Uint8List(certBytes.length + 4);
      fullMessage[0] = TlsHandshakeType.certificate.value;
      fullMessage[1] = (certBytes.length >> 16) & 0xff;
      fullMessage[2] = (certBytes.length >> 8) & 0xff;
      fullMessage[3] = certBytes.length & 0xff;
      fullMessage.setRange(4, fullMessage.length, certBytes);

      final frame = CryptoFrame(offset: 0, data: fullMessage);
      handler.onCryptoFrame(frame);

      expect(handler.peerCertificate, isNotNull);
      expect(handler.peerCertificate, equals(certData));
      expect(handler.peerCertificateVerify, isNull);
    });

    test('stores peer certificate verify bytes', () {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = state_machine.HandshakeStateMachine(
        state_machine.HandshakeRole.client,
      );
      handshakeMachine.start();
      handshakeMachine.onMessage(TlsHandshakeType.clientHello, sent: true);
      handshakeMachine.onMessage(TlsHandshakeType.serverHello, sent: false);
      handshakeMachine.onMessage(
        TlsHandshakeType.encryptedExtensions,
        sent: false,
      );
      handshakeMachine.onMessage(TlsHandshakeType.certificate, sent: false);

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: handshakeMachine,
      );

      final verifyMessage = CertificateVerify(
        signatureScheme: CertificateVerify.ed25519,
        signature: Uint8List.fromList([4, 5, 6]),
      );
      final verifyBytes = verifyMessage.serialize();
      final fullMessage = Uint8List(verifyBytes.length + 4);
      fullMessage[0] = TlsHandshakeType.certificateVerify.value;
      fullMessage[1] = (verifyBytes.length >> 16) & 0xff;
      fullMessage[2] = (verifyBytes.length >> 8) & 0xff;
      fullMessage[3] = verifyBytes.length & 0xff;
      fullMessage.setRange(4, fullMessage.length, verifyBytes);

      final frame = CryptoFrame(offset: 0, data: fullMessage);
      handler.onCryptoFrame(frame);

      expect(handler.peerCertificateVerify, isNotNull);
      expect(handler.peerCertificateVerify, equals(fullMessage));
    });

    test('logs warning and continues safely for malformed Certificate message',
        () {
      final records = <LogRecord>[];
      final sub = Logger('CryptoFrameHandler').onRecord.listen(records.add);
      addTearDown(sub.cancel);

      final assembler = CryptoFrameAssembler();
      final handshakeMachine = state_machine.HandshakeStateMachine(
        state_machine.HandshakeRole.client,
      );
      handshakeMachine.start();
      handshakeMachine.onMessage(TlsHandshakeType.clientHello, sent: true);
      handshakeMachine.onMessage(TlsHandshakeType.serverHello, sent: false);
      handshakeMachine.onMessage(
        TlsHandshakeType.encryptedExtensions,
        sent: false,
      );

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: handshakeMachine,
      );

      // A Certificate handshake message whose payload is too short to parse.
      final malformedCert = Uint8List.fromList([
        TlsHandshakeType.certificate.value,
        0x00,
        0x00,
        0x01, // length: 1
        0x00, // payload: only request_context_length, no certificates_length
      ]);

      final frame = CryptoFrame(offset: 0, data: malformedCert);
      handler.onCryptoFrame(frame);

      expect(handshakeMachine.hasFailed, isFalse);
      expect(handler.peerCertificate, isNull);
      expect(records, hasLength(1));
      expect(records.first.level, Level.WARNING);
      expect(records.first.message, contains('Certificate'));
      expect(records.first.message, contains('TlsHandshakeType.certificate'));
      expect(records.first.error, isNotNull);

      // Handshake continues safely: the next expected message is accepted.
      final verifyMessage = CertificateVerify(
        signatureScheme: CertificateVerify.ed25519,
        signature: Uint8List.fromList([4, 5, 6]),
      );
      final verifyBytes = verifyMessage.serialize();
      final fullVerifyMessage = Uint8List(verifyBytes.length + 4);
      fullVerifyMessage[0] = TlsHandshakeType.certificateVerify.value;
      fullVerifyMessage[1] = (verifyBytes.length >> 16) & 0xff;
      fullVerifyMessage[2] = (verifyBytes.length >> 8) & 0xff;
      fullVerifyMessage[3] = verifyBytes.length & 0xff;
      fullVerifyMessage.setRange(4, fullVerifyMessage.length, verifyBytes);

      handler.onCryptoFrame(
        CryptoFrame(offset: malformedCert.length, data: fullVerifyMessage),
      );
      expect(handshakeMachine.hasFailed, isFalse);
      expect(handler.peerCertificateVerify, isNotNull);
      expect(handshakeMachine.state,
          state_machine.HandshakeState.clientWaitFinished);
    });

    test('forwards ClientHello to HandshakeCoordinator', () async {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = state_machine.HandshakeStateMachine(
        state_machine.HandshakeRole.server,
      );
      handshakeMachine.start();
      handshakeMachine.accept();

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: handshakeMachine,
      );
      final coordinator = _FakeHandshakeCoordinator(
        backend: DefaultCryptoBackend(),
        role: key_exchange.HandshakeRole.server,
        keyManager: KeyManager.forTest(),
      );
      await coordinator.generateKeys();
      handler.coordinator = coordinator;

      final clientHelloPayload = Uint8List.fromList([
        0x03,
        0x03,
        ...List<int>.generate(32, (i) => i),
        0x00,
        0x00,
        0x02,
        0x13,
        0x01,
        0x01,
        0x00,
        0x00,
        0x05,
        0x00,
        0x0d,
        0x00,
        0x02,
        0x01,
        0x00,
      ]);
      final fullMessage = Uint8List(clientHelloPayload.length + 4);
      fullMessage[0] = TlsHandshakeType.clientHello.value;
      fullMessage[1] = (clientHelloPayload.length >> 16) & 0xff;
      fullMessage[2] = (clientHelloPayload.length >> 8) & 0xff;
      fullMessage[3] = clientHelloPayload.length & 0xff;
      fullMessage.setRange(4, fullMessage.length, clientHelloPayload);

      final frame = CryptoFrame(offset: 0, data: fullMessage);
      handler.onCryptoFrame(frame);

      expect(coordinator.processClientHelloCalled, isTrue);
      expect(coordinator.receivedFrame, equals(frame));
    });

    test('marks handshake as failed on invalid transition', () {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = state_machine.HandshakeStateMachine(
        state_machine.HandshakeRole.client,
      );
      handshakeMachine.start();

      final handler = CryptoFrameHandler(
        assembler: assembler,
        handshakeMachine: handshakeMachine,
      );

      final serverHelloPayload = Uint8List.fromList([0, 1, 2, 3]);
      final fullMessage = Uint8List(serverHelloPayload.length + 4);
      fullMessage[0] = TlsHandshakeType.serverHello.value;
      fullMessage[1] = 0;
      fullMessage[2] = 0;
      fullMessage[3] = serverHelloPayload.length;
      fullMessage.setRange(4, fullMessage.length, serverHelloPayload);

      final frame = CryptoFrame(offset: 0, data: fullMessage);
      handler.onCryptoFrame(frame);

      expect(handshakeMachine.hasFailed, isTrue);
    });
  });
}

class _FakeHandshakeCoordinator extends HandshakeCoordinator {
  bool processClientHelloCalled = false;
  CryptoFrame? receivedFrame;

  _FakeHandshakeCoordinator({
    required super.backend,
    required super.role,
    required super.keyManager,
  });

  @override
  Future<SecretKey> processClientHello(CryptoFrame clientHello) async {
    processClientHelloCalled = true;
    receivedFrame = clientHello;
    return SimpleSecretKey(Uint8List(32));
  }
}

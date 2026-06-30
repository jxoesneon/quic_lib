import 'dart:typed_data';

import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/certificate_verify.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_handler.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('CryptoFrameHandler', () {
    test('stores peer certificate bytes', () {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = HandshakeStateMachine(HandshakeRole.client);
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

      final certMessage = CertificateMessage(
        entries: [
          CertificateEntry(certData: Uint8List.fromList([1, 2, 3]))
        ],
      );
      final certBytes = certMessage.serialize();
      final fullMessage = Uint8List(certBytes.length + 1);
      fullMessage[0] = TlsHandshakeType.certificate.value;
      fullMessage.setRange(1, fullMessage.length, certBytes);

      final frame = CryptoFrame(
        offset: 0,
        data: fullMessage,
      );
      handler.onCryptoFrame(frame);

      expect(handler.peerCertificate, isNotNull);
      expect(handler.peerCertificate, equals(fullMessage));
      expect(handler.peerCertificateVerify, isNull);
    });

    test('stores peer certificate verify bytes', () {
      final assembler = CryptoFrameAssembler();
      final handshakeMachine = HandshakeStateMachine(HandshakeRole.client);
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
      final fullMessage = Uint8List(verifyBytes.length + 1);
      fullMessage[0] = TlsHandshakeType.certificateVerify.value;
      fullMessage.setRange(1, fullMessage.length, verifyBytes);

      final frame = CryptoFrame(
        offset: 0,
        data: fullMessage,
      );
      handler.onCryptoFrame(frame);

      expect(handler.peerCertificateVerify, isNotNull);
      expect(handler.peerCertificateVerify, equals(fullMessage));
    });
  });
}

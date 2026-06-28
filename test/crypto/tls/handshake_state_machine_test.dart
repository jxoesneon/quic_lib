import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';

void main() {
  group('HandshakeStateMachine client path', () {
    test('idle -> clientStart', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      expect(sm.state, HandshakeState.idle);
      sm.start();
      expect(sm.state, HandshakeState.clientStart);
      expect(sm.inProgress, isTrue);
    });

    test('clientStart -> clientWaitServerHello on sending ClientHello', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      expect(sm.state, HandshakeState.clientWaitServerHello);
    });

    test(
        'clientWaitServerHello -> clientWaitEncryptedExtensions '
        'on receiving ServerHello', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      expect(sm.state, HandshakeState.clientWaitEncryptedExtensions);
    });

    test(
        'clientWaitEncryptedExtensions -> clientWaitCertificate '
        'on receiving EncryptedExtensions', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      expect(sm.state, HandshakeState.clientWaitCertificate);
    });

    test(
        'clientWaitCertificate -> clientWaitCertVerify '
        'on receiving Certificate', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      sm.onMessage(TlsHandshakeType.certificate, sent: false);
      expect(sm.state, HandshakeState.clientWaitCertVerify);
    });

    test(
        'clientWaitCertVerify -> clientWaitFinished '
        'on receiving CertificateVerify', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      sm.onMessage(TlsHandshakeType.certificate, sent: false);
      sm.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      expect(sm.state, HandshakeState.clientWaitFinished);
    });

    test('clientWaitFinished -> clientConnected on receiving Finished', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      sm.onMessage(TlsHandshakeType.certificate, sent: false);
      sm.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: false);
      expect(sm.state, HandshakeState.clientConnected);
    });

    test('clientConnected -> handshakeComplete on sending Finished', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      sm.onMessage(TlsHandshakeType.certificate, sent: false);
      sm.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: true);
      expect(sm.state, HandshakeState.handshakeComplete);
      expect(sm.isComplete, isTrue);
      expect(sm.inProgress, isFalse);
    });
  });

  group('HandshakeStateMachine server path', () {
    test('idle -> serverStart', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      expect(sm.state, HandshakeState.idle);
      sm.start();
      expect(sm.state, HandshakeState.serverStart);
      expect(sm.inProgress, isTrue);
    });

    test('serverStart -> serverWaitClientHello on accept', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      sm.start();
      sm.accept();
      expect(sm.state, HandshakeState.serverWaitClientHello);
    });

    test(
        'serverWaitClientHello -> serverWaitFinished '
        'on receiving ClientHello', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      sm.start();
      sm.accept();
      sm.onMessage(TlsHandshakeType.clientHello, sent: false);
      expect(sm.state, HandshakeState.serverWaitFinished);
    });

    test('serverWaitFinished allows sending server flight', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      sm.start();
      sm.accept();
      sm.onMessage(TlsHandshakeType.clientHello, sent: false);
      sm.onMessage(TlsHandshakeType.serverHello, sent: true);
      expect(sm.state, HandshakeState.serverWaitFinished);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: true);
      expect(sm.state, HandshakeState.serverWaitFinished);
      sm.onMessage(TlsHandshakeType.certificate, sent: true);
      expect(sm.state, HandshakeState.serverWaitFinished);
      sm.onMessage(TlsHandshakeType.certificateVerify, sent: true);
      expect(sm.state, HandshakeState.serverWaitFinished);
    });

    test('serverWaitFinished -> serverConnected on receiving Finished', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      sm.start();
      sm.accept();
      sm.onMessage(TlsHandshakeType.clientHello, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: false);
      expect(sm.state, HandshakeState.serverConnected);
    });

    test('serverConnected -> handshakeComplete on sending Finished', () {
      final sm = HandshakeStateMachine(HandshakeRole.server);
      sm.start();
      sm.accept();
      sm.onMessage(TlsHandshakeType.clientHello, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: true);
      expect(sm.state, HandshakeState.handshakeComplete);
      expect(sm.isComplete, isTrue);
      expect(sm.inProgress, isFalse);
    });
  });

  group('HandshakeStateMachine fail and reset', () {
    test('fail transitions to handshakeFailed', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.fail();
      expect(sm.state, HandshakeState.handshakeFailed);
      expect(sm.hasFailed, isTrue);
      expect(sm.inProgress, isFalse);
    });

    test('reset returns to idle', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.reset();
      expect(sm.state, HandshakeState.idle);
      // idle is not complete nor failed, so inProgress is true per the spec.
      expect(sm.inProgress, isTrue);
    });

    test('invalid transition throws', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      expect(
        () => sm.onMessage(TlsHandshakeType.serverHello, sent: true),
        throwsA(isA<StateError>()),
      );
    });

    test('double fail is no-op', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.fail();
      sm.fail();
      expect(sm.state, HandshakeState.handshakeFailed);
    });

    test('fail after complete is no-op', () {
      final sm = HandshakeStateMachine(HandshakeRole.client);
      sm.start();
      sm.onMessage(TlsHandshakeType.clientHello, sent: true);
      sm.onMessage(TlsHandshakeType.serverHello, sent: false);
      sm.onMessage(TlsHandshakeType.encryptedExtensions, sent: false);
      sm.onMessage(TlsHandshakeType.certificate, sent: false);
      sm.onMessage(TlsHandshakeType.certificateVerify, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: false);
      sm.onMessage(TlsHandshakeType.finished, sent: true);
      sm.fail();
      expect(sm.state, HandshakeState.handshakeComplete);
    });
  });
}

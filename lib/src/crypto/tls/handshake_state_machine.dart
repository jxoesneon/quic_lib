import 'tls_handshake_types.dart';
import 'package:dart_quic/src/security/rate_limiter.dart';

enum HandshakeState {
  idle,

  // Client path
  clientStart,
  clientWaitServerHello,
  clientWaitEncryptedExtensions,
  clientWaitCertificate,
  clientWaitCertVerify,
  clientWaitFinished,
  clientConnected,

  // Server path
  serverStart,
  serverWaitClientHello,
  serverWaitFinished,
  serverConnected,

  // Terminal
  handshakeFailed,
  handshakeComplete,
}

enum HandshakeRole { client, server }

class HandshakeStateMachine {
  // SECURITY: Rate limit transitions to prevent CPU exhaustion.
  static const int _maxTransitionsPerSecond = 100;
  final RateLimiter _transitionLimiter = RateLimiter(
    maxCalls: _maxTransitionsPerSecond,
    windowMs: 1000,
  );

  final HandshakeRole _role;
  HandshakeState _state = HandshakeState.idle;

  HandshakeStateMachine(this._role);

  HandshakeState get state => _state;
  bool get isComplete => _state == HandshakeState.handshakeComplete;
  bool get hasFailed => _state == HandshakeState.handshakeFailed;
  bool get inProgress => !isComplete && !hasFailed;

  /// Transitions from [idle] to [clientStart] (client) or [serverStart] (server).
  void start() {
    if (_state != HandshakeState.idle) {
      throw StateError('Cannot start from $_state');
    }
    _state = _role == HandshakeRole.client
        ? HandshakeState.clientStart
        : HandshakeState.serverStart;
  }

  /// Server-only: transition from [serverStart] to [serverWaitClientHello].
  void accept() {
    if (_state != HandshakeState.serverStart) {
      throw StateError('Cannot accept from $_state');
    }
    _state = HandshakeState.serverWaitClientHello;
  }

  /// Advance state on sending/receiving handshake messages.
  /// [messageType] is the TLS handshake message type.
  /// [sent] is true if we sent it, false if we received it.
  void onMessage(TlsHandshakeType messageType, {required bool sent}) {
    // SECURITY: Rate limit transitions.
    _transitionLimiter.checkOrThrow(
      DateTime.now().millisecondsSinceEpoch,
      label: 'handshake state transitions',
    );
    switch (_state) {
      case HandshakeState.clientStart:
        if (sent && messageType == TlsHandshakeType.clientHello) {
          _state = HandshakeState.clientWaitServerHello;
          return;
        }
        break;
      case HandshakeState.clientWaitServerHello:
        if (!sent && messageType == TlsHandshakeType.serverHello) {
          _state = HandshakeState.clientWaitEncryptedExtensions;
          return;
        }
        break;
      case HandshakeState.clientWaitEncryptedExtensions:
        if (!sent && messageType == TlsHandshakeType.encryptedExtensions) {
          _state = HandshakeState.clientWaitCertificate;
          return;
        }
        break;
      case HandshakeState.clientWaitCertificate:
        if (!sent && messageType == TlsHandshakeType.certificate) {
          _state = HandshakeState.clientWaitCertVerify;
          return;
        }
        break;
      case HandshakeState.clientWaitCertVerify:
        if (!sent && messageType == TlsHandshakeType.certificateVerify) {
          _state = HandshakeState.clientWaitFinished;
          return;
        }
        break;
      case HandshakeState.clientWaitFinished:
        if (!sent && messageType == TlsHandshakeType.finished) {
          _state = HandshakeState.clientConnected;
          return;
        }
        break;
      case HandshakeState.clientConnected:
        if (sent && messageType == TlsHandshakeType.finished) {
          _state = HandshakeState.handshakeComplete;
          return;
        }
        break;
      case HandshakeState.serverWaitClientHello:
        if (!sent && messageType == TlsHandshakeType.clientHello) {
          _state = HandshakeState.serverWaitFinished;
          return;
        }
        break;
      case HandshakeState.serverWaitFinished:
        if (!sent && messageType == TlsHandshakeType.finished) {
          _state = HandshakeState.serverConnected;
          return;
        }
        if (sent &&
            (messageType == TlsHandshakeType.serverHello ||
                messageType == TlsHandshakeType.encryptedExtensions ||
                messageType == TlsHandshakeType.certificate ||
                messageType == TlsHandshakeType.certificateVerify)) {
          // Server flight sent while waiting for client Finished.
          return;
        }
        break;
      case HandshakeState.serverConnected:
        if (sent && messageType == TlsHandshakeType.finished) {
          _state = HandshakeState.handshakeComplete;
          return;
        }
        break;
      case HandshakeState.idle:
      case HandshakeState.serverStart:
      case HandshakeState.handshakeFailed:
      case HandshakeState.handshakeComplete:
        // No valid message transitions from these states.
        break;
    }
    throw StateError(
      'Invalid message $messageType (sent=$sent) in state $_state',
    );
  }

  /// Mark handshake as failed.
  void fail() {
    if (_state == HandshakeState.handshakeComplete ||
        _state == HandshakeState.handshakeFailed) {
      return;
    }
    _state = HandshakeState.handshakeFailed;
  }

  /// Reset to idle.
  void reset() {
    _state = HandshakeState.idle;
  }
}

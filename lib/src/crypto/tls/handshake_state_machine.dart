import 'tls_handshake_types.dart';
import 'package:quic_lib/src/security/rate_limiter.dart';

/// Discrete states of the TLS 1.3 handshake state machine (RFC 8446).
///
/// Each value represents a specific point in the client or server handshake
/// flow. The state machine advances in response to sending or receiving TLS
/// handshake messages such as [TlsHandshakeType.clientHello] and
/// [TlsHandshakeType.serverHello].
///
/// See also:
/// - [HandshakeStateMachine] — manages transitions between these states.
/// - [HandshakeRole] — distinguishes client and server endpoints.
enum HandshakeState {
  /// No handshake in progress.
  idle,

  // Client path
  /// Client has sent ClientHello.
  clientStart,

  /// Client waiting for ServerHello from the server.
  clientWaitServerHello,

  /// Client waiting for EncryptedExtensions from the server.
  clientWaitEncryptedExtensions,

  /// Client waiting for Certificate from the server.
  clientWaitCertificate,

  /// Client waiting for CertificateVerify from the server.
  clientWaitCertVerify,

  /// Client waiting for Finished from the server.
  clientWaitFinished,

  /// Client handshake complete.
  clientConnected,

  // Server path
  /// Server waiting for ClientHello from the client.
  serverStart,

  /// Server waiting for ClientHello key_share / full message.
  serverWaitClientHello,

  /// Server waiting for Finished from the client.
  serverWaitFinished,

  /// Server handshake complete.
  serverConnected,

  // Terminal
  /// Handshake failed (e.g., bad certificate, timeout).
  handshakeFailed,

  /// Handshake completed successfully.
  handshakeComplete,
}

/// Role of the endpoint in the TLS handshake.
enum HandshakeRole {
  /// This endpoint is acting as the TLS client.
  client,

  /// This endpoint is acting as the TLS server.
  server,
}

/// Manages the TLS 1.3 handshake lifecycle for a single QUIC connection (RFC 8446).
///
/// [HandshakeStateMachine] tracks which handshake messages have been sent and
/// received, enforcing valid state transitions and preventing illegal message
/// sequences. It is used by both client and server endpoints; the exact path
/// is determined by [HandshakeRole].
///
/// The machine is rate-limited to prevent CPU exhaustion from malicious peers
/// that might flood handshake messages.
///
/// ## Example
/// ```dart
/// final machine = HandshakeStateMachine(HandshakeRole.client);
/// machine.start();
/// machine.onMessage(TlsHandshakeType.clientHello, sent: true);
/// ```
///
/// See also:
/// - [HandshakeState] — the individual states this machine transitions through.
/// - [TlsHandshakeType] — the message types that drive state changes.
/// - RFC 8446 Section 4 — handshake protocol overview.
class HandshakeStateMachine {
  // SECURITY: Rate limit transitions to prevent CPU exhaustion.
  static const int _maxTransitionsPerSecond = 100;
  final RateLimiter _transitionLimiter = RateLimiter(
    maxCalls: _maxTransitionsPerSecond,
    windowMs: 1000,
  );

  final HandshakeRole _role;
  HandshakeState _state = HandshakeState.idle;

  /// Creates a [HandshakeStateMachine] for the given [HandshakeRole].
  ///
  /// The initial state is [HandshakeState.idle].
  HandshakeStateMachine(this._role);

  HandshakeState get state => _state;
  bool get isComplete => _state == HandshakeState.handshakeComplete;
  bool get hasFailed => _state == HandshakeState.handshakeFailed;
  bool get inProgress => !isComplete && !hasFailed;

  /// Transitions from [HandshakeState.idle] to [HandshakeState.clientStart] (client) or [HandshakeState.serverStart] (server).
  void start() {
    if (_state != HandshakeState.idle) {
      throw StateError('Cannot start from $_state');
    }
    _state = _role == HandshakeRole.client
        ? HandshakeState.clientStart
        : HandshakeState.serverStart;
  }

  /// Server-only: transition from [HandshakeState.serverStart] to [HandshakeState.serverWaitClientHello].
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

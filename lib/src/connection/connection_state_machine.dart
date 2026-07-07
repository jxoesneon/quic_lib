import 'dart:async';

import 'package:quic_lib/src/logging/quic_logger.dart';
import 'package:quic_lib/src/security/rate_limiter.dart';

/// The states of a QUIC connection lifecycle.
///
/// Valid transitions:
/// - idle → handshaking (on connect/bind)
/// - handshaking → established (on handshake complete)
/// - handshaking → closed (on handshake failure/timeout)
/// - established → closing (on close initiated)
/// - established → draining (on CONNECTION_CLOSE received)
/// - closing → closed (after close timeout)
/// - draining → closed (after drain timeout)
/// - Any → closed (on immediate abort)
enum ConnectionState {
  /// Waiting for a connection to be initiated.
  idle,

  /// TLS handshake and address validation in progress.
  handshaking,

  /// Handshake complete; application data may flow.
  established,

  /// Close initiated by this endpoint; draining outgoing packets.
  closing,

  /// Connection fully terminated.
  closed,

  /// Peer-initiated close received; draining incoming packets.
  draining,
}

/// Manages the QUIC connection lifecycle state machine.
///
/// Throws [StateError] for invalid state transitions and emits state changes
/// via [onStateChanged].
class ConnectionStateMachine {
  /// Creates a connection state machine starting in [ConnectionState.idle].
  ConnectionStateMachine();

  // SECURITY: Rate limit state transitions to prevent CPU exhaustion.
  static const int _maxTransitionsPerSecond = 100;
  final RateLimiter _transitionLimiter = RateLimiter(
    maxCalls: _maxTransitionsPerSecond,
    windowMs: 1000,
  );

  ConnectionState _state = ConnectionState.idle;
  final StreamController<ConnectionState> _stateController =
      StreamController<ConnectionState>.broadcast();

  /// Current connection lifecycle state.
  ConnectionState get state => _state;

  /// `true` while the connection has not yet started handshaking.
  bool get isIdle => _state == ConnectionState.idle;

  /// `true` while the TLS handshake and address validation are in progress.
  bool get isHandshaking => _state == ConnectionState.handshaking;

  /// `true` once the handshake has completed and application data may flow.
  bool get isEstablished => _state == ConnectionState.established;

  /// `true` after this endpoint has initiated a graceful close.
  bool get isClosing => _state == ConnectionState.closing;

  /// `true` once the connection has fully terminated.
  bool get isClosed => _state == ConnectionState.closed;

  /// `true` after a CONNECTION_CLOSE was received from the peer.
  bool get isDraining => _state == ConnectionState.draining;

  /// `true` when the endpoint is allowed to send application data.
  bool get canSendData =>
      _state == ConnectionState.established ||
      _state == ConnectionState.closing;

  /// `true` when the endpoint is allowed to receive application data.
  bool get canReceiveData =>
      _state == ConnectionState.established ||
      _state == ConnectionState.handshaking;

  /// Listen to state changes.
  Stream<ConnectionState> get onStateChanged => _stateController.stream;

  /// Transitions the connection to [newState].
  ///
  /// If [reason] is provided, it is logged to stdout.
  ///
  /// Throws [StateError] if the transition is not allowed or if the rate
  /// limit for transitions is exceeded.
  void transitionTo(ConnectionState newState, {String? reason}) {
    if (_state == newState) {
      // No-op; still log if a reason was given.
      if (reason != null && reason.isNotEmpty) {
        QuicLogger.log('[ConnectionStateMachine] staying in $_state: $reason');
      }
      return;
    }

    // SECURITY: Rate limit transitions.
    _transitionLimiter.checkOrThrow(
      DateTime.now().millisecondsSinceEpoch,
      label: 'connection state transitions',
    );

    if (!_isValidTransition(_state, newState)) {
      throw StateError(
        'Invalid connection state transition from $_state to $newState',
      );
    }

    if (reason != null && reason.isNotEmpty) {
      QuicLogger.log('[ConnectionStateMachine] $_state → $newState: $reason');
    }

    _state = newState;
    _stateController.add(newState);
  }

  /// Disposes the underlying state-change stream controller.
  void dispose() {
    _stateController.close();
  }

  static bool _isValidTransition(ConnectionState from, ConnectionState to) {
    switch (from) {
      case ConnectionState.idle:
        return to == ConnectionState.handshaking ||
            to == ConnectionState.closed;
      case ConnectionState.handshaking:
        return to == ConnectionState.established ||
            to == ConnectionState.closed;
      case ConnectionState.established:
        return to == ConnectionState.closing ||
            to == ConnectionState.draining ||
            to == ConnectionState.closed;
      case ConnectionState.closing:
        return to == ConnectionState.closed;
      case ConnectionState.draining:
        return to == ConnectionState.closed;
      case ConnectionState.closed:
        // Terminal state — no further transitions allowed.
        return false;
    }
  }
}

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
  idle,
  handshaking,
  established,
  closing,
  closed,
  draining,
}

/// Manages the QUIC connection lifecycle state machine.
///
/// Throws [StateError] for invalid state transitions and emits state changes
/// via [onStateChanged].
class ConnectionStateMachine {
  // SECURITY: Rate limit state transitions to prevent CPU exhaustion.
  static const int _maxTransitionsPerSecond = 100;
  final RateLimiter _transitionLimiter = RateLimiter(
    maxCalls: _maxTransitionsPerSecond,
    windowMs: 1000,
  );

  ConnectionState _state = ConnectionState.idle;
  final StreamController<ConnectionState> _stateController =
      StreamController<ConnectionState>.broadcast();

  ConnectionState get state => _state;

  bool get isIdle => _state == ConnectionState.idle;
  bool get isHandshaking => _state == ConnectionState.handshaking;
  bool get isEstablished => _state == ConnectionState.established;
  bool get isClosing => _state == ConnectionState.closing;
  bool get isClosed => _state == ConnectionState.closed;
  bool get isDraining => _state == ConnectionState.draining;

  bool get canSendData =>
      _state == ConnectionState.established ||
      _state == ConnectionState.closing;

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

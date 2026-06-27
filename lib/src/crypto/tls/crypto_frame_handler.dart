import 'dart:async';

import 'package:dart_quic/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:dart_quic/src/crypto/tls/crypto_message_parser.dart';
import 'package:dart_quic/src/crypto/tls/handshake_coordinator.dart';
import 'package:dart_quic/src/crypto/tls/handshake_state_machine.dart';
import 'package:dart_quic/src/crypto/tls/tls_handshake_types.dart';
import 'package:dart_quic/src/wire/frame.dart';

/// Receives CRYPTO frames, assembles them, and forwards parsed TLS handshake
/// messages to the [HandshakeStateMachine].
class CryptoFrameHandler {
  final CryptoFrameAssembler _assembler;
  final HandshakeStateMachine _handshakeMachine;
  HandshakeCoordinator? _coordinator;

  CryptoFrameHandler({
    required CryptoFrameAssembler assembler,
    required HandshakeStateMachine handshakeMachine,
  })  : _assembler = assembler,
        _handshakeMachine = handshakeMachine;

  /// Attach a [HandshakeCoordinator] to receive parsed ClientHello frames.
  set coordinator(HandshakeCoordinator c) => _coordinator = c;

  /// Deliver a [CryptoFrame] to the assembler and, for each contiguous
  /// assembled message, parse its TLS handshake type and notify the state
  /// machine.
  ///
  /// Because this path only handles received frames, [sent] is always
  /// `false` when calling [HandshakeStateMachine.onMessage].
  ///
  /// Invalid state transitions (e.g., out-of-order or unexpected messages)
  /// are caught and cause the handshake to fail rather than crash the
  /// connection.
  void onCryptoFrame(CryptoFrame frame) {
    final messages = _assembler.deliver(frame);
    for (final message in messages) {
      final type = parseMessageType(message);
      if (type != null) {
        try {
          _handshakeMachine.onMessage(type, sent: false);
        } on StateError {
          // Invalid transition — mark handshake as failed.
          _handshakeMachine.fail();
        }
        if (_coordinator != null && type == TlsHandshakeType.clientHello) {
          unawaited(_coordinator!.processClientHello(frame));
        }
      }
    }
  }
}

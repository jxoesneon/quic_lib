import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/wire/frame.dart';

/// Receives CRYPTO frames, assembles them, and forwards parsed TLS handshake
/// messages to the [HandshakeStateMachine].
class CryptoFrameHandler {
  final CryptoFrameAssembler _assembler;
  final HandshakeStateMachine _handshakeMachine;

  CryptoFrameHandler({
    required CryptoFrameAssembler assembler,
    required HandshakeStateMachine handshakeMachine,
  })  : _assembler = assembler,
        _handshakeMachine = handshakeMachine;

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
      }
    }
  }
}

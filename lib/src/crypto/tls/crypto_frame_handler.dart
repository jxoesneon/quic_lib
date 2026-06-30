import 'dart:async';
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:quic_lib/src/crypto/tls/certificate_message.dart';
import 'package:quic_lib/src/crypto/tls/crypto_frame_assembler.dart';
import 'package:quic_lib/src/crypto/tls/crypto_message_parser.dart';
import 'package:quic_lib/src/crypto/tls/handshake_coordinator.dart';
import 'package:quic_lib/src/crypto/tls/handshake_state_machine.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';
import 'package:quic_lib/src/wire/frame.dart';

final Logger _logger = Logger('CryptoFrameHandler');

/// Receives CRYPTO frames, assembles them, and forwards parsed TLS handshake
/// messages to the [HandshakeStateMachine].
class CryptoFrameHandler {
  final CryptoFrameAssembler _assembler;
  final HandshakeStateMachine _handshakeMachine;
  HandshakeCoordinator? _coordinator;

  /// Raw bytes of the peer's most recent TLS Certificate message, if any.
  Uint8List? _peerCertificate;

  /// Raw bytes of the peer's most recent TLS CertificateVerify message, if any.
  Uint8List? _peerCertificateVerify;

  CryptoFrameHandler({
    required CryptoFrameAssembler assembler,
    required HandshakeStateMachine handshakeMachine,
  })  : _assembler = assembler,
        _handshakeMachine = handshakeMachine;

  /// Attach a [HandshakeCoordinator] to receive parsed ClientHello frames.
  set coordinator(HandshakeCoordinator c) => _coordinator = c;

  /// Raw bytes of the peer's TLS Certificate message, or null if not yet
  /// received.
  Uint8List? get peerCertificate => _peerCertificate;

  /// Raw bytes of the peer's TLS CertificateVerify message, or null if not yet
  /// received.
  Uint8List? get peerCertificateVerify => _peerCertificateVerify;

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
        if (type == TlsHandshakeType.certificate) {
          try {
            final parsed = parseMessage(message);
            final certMessage = CertificateMessage.parse(parsed.payload);
            if (certMessage.entries.isNotEmpty) {
              _peerCertificate =
                  Uint8List.fromList(certMessage.entries.first.certData);
            }
          } catch (e, stackTrace) {
            _logger.warning(
              'Failed to parse TLS Certificate message '
              '(handshake type: $type)',
              e,
              stackTrace,
            );
          }
        } else if (type == TlsHandshakeType.certificateVerify) {
          _peerCertificateVerify = Uint8List.fromList(message);
        }
      }
    }
  }
}

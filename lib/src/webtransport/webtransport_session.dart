import 'dart:typed_data';

import 'package:quic_lib/src/logging/quic_logger.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Manages the state of a single WebTransport session over HTTP/3.
///
/// Per RFC 9220, a session is identified by its bidirectional stream ID and
/// communicates via capsules on that stream.
class WebTransportSession {
  final int _sessionId;
  bool _isDraining = false;
  bool _isClosed = false;

  WebTransportSession(this._sessionId);

  /// The QUIC stream ID that serves as this session's identifier.
  int get sessionId => _sessionId;

  /// Whether the peer has initiated a drain.
  bool get isDraining => _isDraining;

  /// Whether the session is fully closed.
  bool get isClosed => _isClosed;

  /// Whether the session is still active (not draining and not closed).
  bool get isActive => !_isDraining && !_isClosed;

  /// Process an incoming capsule received on the session's control stream.
  void onCapsuleReceived(Capsule capsule) {
    switch (capsule.type) {
      case CapsuleType.closeWebTransportSession:
        _isClosed = true;
        QuicLogger.log('WebTransportSession($_sessionId): received CLOSE');
      case CapsuleType.drainWebTransportSession:
        _isDraining = true;
      default:
        // Unknown/extension capsules are ignored per RFC 9220.
        break;
    }
  }

  /// Initiate a graceful close of this session.
  ///
  /// Returns a [Capsule] of type [CapsuleType.closeWebTransportSession] whose
  /// payload is encoded per RFC 9220 Section 4.2:
  ///   Error Code (i), [Error Phrase Length (i), Error Phrase (..)]
  Capsule initiateClose({int errorCode = 0, String? reasonPhrase}) {
    final builder = BytesBuilder();

    // Error Code
    builder.add(VarInt.encode(errorCode));

    // Optional reason phrase
    if (reasonPhrase != null && reasonPhrase.isNotEmpty) {
      final phraseBytes = Uint8List.fromList(reasonPhrase.codeUnits);
      builder.add(VarInt.encode(phraseBytes.length));
      builder.add(phraseBytes);
    }

    return Capsule(
      type: CapsuleType.closeWebTransportSession,
      payload: builder.toBytes(),
    );
  }

  /// Initiate a drain of this session.
  ///
  /// Returns a [Capsule] of type [CapsuleType.drainWebTransportSession] with
  /// an empty payload, per RFC 9220 Section 4.3.
  Capsule initiateDrain() {
    return Capsule(
      type: CapsuleType.drainWebTransportSession,
      payload: Uint8List(0),
    );
  }

  /// Called when the locally-initiated CLOSE has been acknowledged.
  void onCloseAcknowledged() {
    _isClosed = true;
  }
}

import 'dart:typed_data';

import 'package:dart_quic/src/logging/quic_logger.dart';
import 'package:dart_quic/src/webtransport/capsule_types.dart';
import 'package:dart_quic/src/webtransport/goaway_capsule.dart';
import 'package:dart_quic/src/wire/varint.dart';

/// Manages the state of a single WebTransport session over HTTP/3.
///
/// Per RFC 9220, a session is identified by its bidirectional stream ID and
/// communicates via capsules on that stream.
class WebTransportSession {
  final int _sessionId;
  bool _isDraining = false;
  bool _isClosed = false;
  bool _receivedGoaway = false;

  WebTransportSession(this._sessionId);

  /// The QUIC stream ID that serves as this session's identifier.
  int get sessionId => _sessionId;

  /// Whether the peer has initiated a drain.
  bool get isDraining => _isDraining;

  /// Whether the session is fully closed.
  bool get isClosed => _isClosed;

  /// Whether the session is still active (not draining and not closed).
  bool get isActive => !_isDraining && !_isClosed;

  /// Whether a GOAWAY capsule has been received from the peer.
  bool get receivedGoaway => _receivedGoaway;

  final List<Uint8List> _receivedDatagrams = [];
  final List<int> _registeredBidirectionalStreams = [];
  final List<int> _registeredUnidirectionalStreams = [];

  /// Datagrams received via [CapsuleType.datagram] capsules.
  List<Uint8List> get receivedDatagrams => List.unmodifiable(_receivedDatagrams);

  /// Bidirectional stream IDs registered via [CapsuleType.registerBidirectionalStream] capsules.
  List<int> get registeredBidirectionalStreams => List.unmodifiable(_registeredBidirectionalStreams);

  /// Unidirectional stream IDs registered via [CapsuleType.registerUnidirectionalStream] capsules.
  List<int> get registeredUnidirectionalStreams => List.unmodifiable(_registeredUnidirectionalStreams);

  /// Process an incoming capsule received on the session's control stream.
  void onCapsuleReceived(Capsule capsule) {
    switch (capsule.type) {
      case CapsuleType.datagram:
        _receivedDatagrams.add(Uint8List.fromList(capsule.payload));
      case CapsuleType.closeWebTransportSession:
        _isClosed = true;
        QuicLogger.log('WebTransportSession($_sessionId): received CLOSE');
      case CapsuleType.drainWebTransportSession:
        _isDraining = true;
      case CapsuleType.registerBidirectionalStream:
        final streamId = VarInt.decode(Uint8List.fromList(capsule.payload).buffer);
        _registeredBidirectionalStreams.add(streamId);
      case CapsuleType.registerUnidirectionalStream:
        final streamId = VarInt.decode(Uint8List.fromList(capsule.payload).buffer);
        _registeredUnidirectionalStreams.add(streamId);
      case CapsuleType.goaway:
        _receivedGoaway = true;
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

  /// Send a datagram via a [Capsule] of type [CapsuleType.datagram].
  ///
  /// Per RFC 9220 Section 5, the capsule payload carries the datagram.
  Capsule sendDatagram(Uint8List data) {
    return Capsule(
      type: CapsuleType.datagram,
      payload: data,
    );
  }

  /// Send a GOAWAY capsule to signal that no new sessions will be accepted.
  ///
  /// Optionally includes the last stream ID that will be processed.
  GoawayCapsule sendGoaway({int? streamId}) {
    return GoawayCapsule(streamId: streamId);
  }

  /// Called when the locally-initiated CLOSE has been acknowledged.
  void onCloseAcknowledged() {
    _isClosed = true;
  }
}

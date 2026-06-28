import 'dart:typed_data';

import 'package:quic_lib/src/logging/quic_logger.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/webtransport/goaway_capsule.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Manages the state of a single WebTransport session over HTTP/3.
///
/// A [WebTransportSession] represents one WebTransport session mapped onto
/// a QUIC bidirectional stream (the session's control stream). Per RFC 9220,
/// endpoints exchange typed capsules on this stream to open streams, send
/// datagrams, drain, or close the session.
///
/// The session tracks incoming capsules via [onCapsuleReceived], surfacing
/// registered stream IDs and received datagrams. Callers can initiate a
/// graceful close with [initiateClose], or send a drain signal with
/// [initiateDrain].
///
/// ## Example
/// ```dart
/// final session = WebTransportSession(0);
///
/// // Process an incoming datagram capsule.
/// session.onCapsuleReceived(Capsule(
///   type: CapsuleType.datagram,
///   payload: Uint8List.fromList([1, 2, 3]),
/// ));
/// print('Datagrams: ${session.receivedDatagrams.length}');
///
/// // Gracefully close the session with an error code.
/// final closeCapsule = session.initiateClose(
///   errorCode: 0,
///   reasonPhrase: 'done',
/// );
/// print('Session closed: ${session.isClosed}');
/// ```
///
/// See also:
/// - [Http3Connection] — the HTTP/3 layer that carries WebTransport capsules.
/// - [Capsule] — a typed capsule exchanged on the session's control stream.
/// - RFC 9220 — WebTransport over HTTP/3.
class WebTransportSession {
  final int _sessionId;
  bool _isDraining = false;
  bool _isClosed = false;
  bool _receivedGoaway = false;

  WebTransportSession(this._sessionId);

  /// The QUIC stream ID that serves as this session's identifier.
  ///
  /// Per RFC 9220, the session ID is the stream ID of the bidirectional
  /// control stream on which capsules are exchanged.
  int get sessionId => _sessionId;

  /// Whether the peer has initiated a drain.
  ///
  /// Set to true when a `DRAIN_WEBTRANSPORT_SESSION` capsule is received.
  /// A draining session should finish existing streams but not open new ones.
  bool get isDraining => _isDraining;

  /// Whether the session is fully closed.
  ///
  /// True once either a `CLOSE_WEBTRANSPORT_SESSION` capsule has been
  /// received, or [initiateClose] has been called and acknowledged.
  bool get isClosed => _isClosed;

  /// Whether the session is still active (not draining and not closed).
  bool get isActive => !_isDraining && !_isClosed;

  /// Whether a GOAWAY capsule has been received from the peer.
  ///
  /// A GOAWAY signals that the server will no longer accept new sessions.
  /// Existing sessions and streams may continue until they complete.
  bool get receivedGoaway => _receivedGoaway;

  final List<Uint8List> _receivedDatagrams = [];
  final List<int> _registeredBidirectionalStreams = [];
  final List<int> _registeredUnidirectionalStreams = [];

  /// Datagrams received via [CapsuleType.datagram] capsules.
  ///
  /// Each entry is a copy of the capsule payload. The list is unmodifiable;
  /// use [onCapsuleReceived] to append new datagrams.
  List<Uint8List> get receivedDatagrams =>
      List.unmodifiable(_receivedDatagrams);

  /// Bidirectional stream IDs registered by the peer.
  ///
  /// Populated when `REGISTER_BIDIRECTIONAL_STREAM` capsules are received.
  /// The returned list is unmodifiable.
  List<int> get registeredBidirectionalStreams =>
      List.unmodifiable(_registeredBidirectionalStreams);

  /// Unidirectional stream IDs registered by the peer.
  ///
  /// Populated when `REGISTER_UNIDIRECTIONAL_STREAM` capsules are received.
  /// The returned list is unmodifiable.
  List<int> get registeredUnidirectionalStreams =>
      List.unmodifiable(_registeredUnidirectionalStreams);

  /// Handle an incoming capsule on the session's control stream.
  ///
  /// Routes the capsule to the appropriate internal state based on its type:
  /// - [CapsuleType.datagram] — appends payload to [receivedDatagrams].
  /// - [CapsuleType.closeWebTransportSession] — marks [isClosed] true.
  /// - [CapsuleType.drainWebTransportSession] — marks [isDraining] true.
  /// - [CapsuleType.registerBidirectionalStream] — adds stream ID to
  ///   [registeredBidirectionalStreams].
  /// - [CapsuleType.registerUnidirectionalStream] — adds stream ID to
  ///   [registeredUnidirectionalStreams].
  /// - [CapsuleType.goaway] — sets [receivedGoaway] true.
  ///
  /// Unknown or extension capsules are silently ignored per RFC 9220.
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
        final streamId =
            VarInt.decode(Uint8List.fromList(capsule.payload).buffer);
        _registeredBidirectionalStreams.add(streamId);
      case CapsuleType.registerUnidirectionalStream:
        final streamId =
            VarInt.decode(Uint8List.fromList(capsule.payload).buffer);
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
  /// Builds a [Capsule] of type [CapsuleType.closeWebTransportSession] whose
  /// payload is a varint [errorCode] followed by an optional reason phrase
  /// encoded per RFC 9220 Section 4.2:
  ///
  /// ```
  /// Error Code (i), [Error Phrase Length (i), Error Phrase (..)]
  /// ```
  ///
  /// The caller must send the returned capsule on the session's control
  /// stream. [isClosed] is not set to true until [onCloseAcknowledged] is
  /// called (or the peer sends its own close capsule).
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

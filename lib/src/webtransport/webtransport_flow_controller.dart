import 'dart:typed_data';

import 'package:quic_lib/src/logging/quic_logger.dart';
import 'package:quic_lib/src/webtransport/capsule_types.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// End-to-end WebTransport flow-control enforcement (RFC 9220 §3).
///
/// A [WebTransportFlowController] tracks the byte-level credit that governs how
/// much data an endpoint may send to, and is willing to receive from, its peer.
/// Credit is tracked at two granularities:
///
/// * **Session-level** — a single budget covering all datagrams and stream data
///   on the session.
/// * **Stream-level** — an independent budget per registered QUIC stream.
///
/// The controller both *enforces* outgoing limits (blocking or throwing when a
/// send would exceed the available credit) and *processes* incoming
/// flow-control capsules to keep the peer's advertised limits up to date. It
/// can also build the capsules an endpoint sends to grant, raise, or drain
/// credit.
///
/// ## Capsule payload formats
///
/// * [CapsuleType.webtransportMaxData] — `VarInt(maxData)`.
/// * [CapsuleType.webtransportMaxStreamData] — `VarInt(streamId) + VarInt(maxData)`.
/// * [CapsuleType.drainCapabilities] — `VarInt(newSessionCredit)`.
///
/// ## Example
/// ```dart
/// final fc = WebTransportFlowController(
///   initialSessionSendCredit: 1024,
///   initialSessionReceiveCredit: 1024,
/// );
///
/// // Sending consumes credit; throws when exhausted.
/// fc.send(512);
/// print(fc.availableSessionSendCredit); // 512
///
/// // An incoming grant raises the limit.
/// fc.processCapsule(WebTransportCapsule(
///   type: CapsuleType.webtransportMaxData,
///   payload: VarInt.encode(4096),
/// ));
/// print(fc.availableSessionSendCredit); // 3584
///
/// // The receiver can drain credit back down.
/// fc.processCapsule(WebTransportCapsule(
///   type: CapsuleType.drainCapabilities,
///   payload: VarInt.encode(256),
/// ));
/// print(fc.availableSessionSendCredit); // 256
/// ```
///
/// See also:
/// - [WebTransportSession] — owns a flow controller and enforces it on sends.
/// - [CapsuleType.webtransportMaxData] / [CapsuleType.drainCapabilities] — the
///   capsules this controller produces and consumes.
/// - RFC 9220 §3 — WebTransport flow control.
class WebTransportFlowController {
  /// Maximum allowed flow-control credit in bytes (256 MB).
  ///
  /// Incoming limits are clamped to this value to prevent unbounded growth or
  /// integer-overflow issues.
  static const int maxCredit = 256 * 1024 * 1024; // 256 MB

  final int _sessionId;
  int _sessionSendCredit;
  int _sessionReceiveCredit;
  int _sessionReceiveConsumed;
  int _advertisedReceiveLimit;
  int _nextReceiveLimit;

  final Map<int, int> _streamSendCredit = {};
  final Map<int, int> _streamReceiveCredit = {};
  final Map<int, int> _streamReceiveConsumed = {};
  final Map<int, int> _advertisedStreamReceiveLimit = {};

  /// Creates a flow controller for the session identified by [sessionId].
  ///
  /// [initialSessionSendCredit] is the session-level send budget granted by the
  /// peer (via an initial `WEBTRANSPORT_MAX_DATA` capsule or transport
  /// parameter). [initialSessionReceiveCredit] is the session-level receive
  /// budget this endpoint advertises to the peer. Both default to [maxCredit]
  /// so that, absent explicit negotiation, sends are not artificially
  /// constrained.
  WebTransportFlowController({
    required int sessionId,
    int initialSessionSendCredit = maxCredit,
    int initialSessionReceiveCredit = maxCredit,
  })  : _sessionId = sessionId,
        _sessionSendCredit =
            initialSessionSendCredit.clamp(0, maxCredit).toInt(),
        _sessionReceiveCredit =
            initialSessionReceiveCredit.clamp(0, maxCredit).toInt(),
        _advertisedReceiveLimit =
            initialSessionReceiveCredit.clamp(0, maxCredit).toInt(),
        _nextReceiveLimit =
            initialSessionReceiveCredit.clamp(0, maxCredit).toInt(),
        _sessionReceiveConsumed = 0;

  /// The session ID this controller is bound to.
  int get sessionId => _sessionId;

  /// Bytes of session-level send credit remaining.
  int get availableSessionSendCredit => _sessionSendCredit;

  /// Whether the session-level send budget is exhausted.
  bool get isSessionSendBlocked => _sessionSendCredit <= 0;

  /// Bytes of session-level receive credit remaining.
  int get availableSessionReceiveCredit =>
      _sessionReceiveCredit - _sessionReceiveConsumed;

  /// Bytes of send credit remaining for [streamId].
  ///
  /// Returns [maxCredit] when the stream has not been explicitly bounded, so
  /// that unregistered streams are not artificially constrained.
  int availableStreamSendCredit(int streamId) =>
      _streamSendCredit[streamId] ?? maxCredit;

  /// Whether the send budget for [streamId] is exhausted.
  bool isStreamSendBlocked(int streamId) =>
      availableStreamSendCredit(streamId) <= 0;

  /// Bytes of receive credit remaining for [streamId].
  int availableStreamReceiveCredit(int streamId) {
    final limit = _streamReceiveCredit[streamId] ?? maxCredit;
    final consumed = _streamReceiveConsumed[streamId] ?? 0;
    return limit - consumed;
  }

  /// All stream IDs for which a per-stream send limit has been negotiated.
  List<int> get trackedSendStreams => List.unmodifiable(_streamSendCredit.keys);

  /// All stream IDs for which a per-stream receive limit has been negotiated.
  List<int> get trackedReceiveStreams =>
      List.unmodifiable(_streamReceiveCredit.keys);

  /// Attempts to consume [bytes] of send credit.
  ///
  /// Checks both the session-level budget and, when [streamId] is supplied, the
  /// per-stream budget. Returns `true` and consumes the credit when enough is
  /// available; returns `false` without consuming anything when the send would
  /// exceed the available credit.
  ///
  /// Throws [ArgumentError] if [bytes] is negative.
  bool trySend(int bytes, {int? streamId}) {
    if (bytes < 0) {
      throw ArgumentError('bytes must be non-negative, got $bytes');
    }
    if (bytes == 0) return true;

    if (bytes > _sessionSendCredit) return false;
    if (streamId != null) {
      final streamBudget = _streamSendCredit[streamId] ?? maxCredit;
      if (bytes > streamBudget) return false;
    }

    _sessionSendCredit -= bytes;
    if (streamId != null) {
      _streamSendCredit.update(
        streamId,
        (v) => v - bytes,
        ifAbsent: () => maxCredit - bytes,
      );
    }
    return true;
  }

  /// Consumes [bytes] of send credit, throwing if credit is exhausted.
  ///
  /// Like [trySend] but throws a [StateError] describing which budget was
  /// exhausted instead of returning `false`. Use this when the caller prefers
  /// exception-based control flow over a boolean result.
  void send(int bytes, {int? streamId}) {
    if (!trySend(bytes, streamId: streamId)) {
      if (streamId != null && bytes > availableStreamSendCredit(streamId)) {
        throw StateError(
          'WebTransport stream $streamId send credit exhausted: '
          'need $bytes bytes, have ${availableStreamSendCredit(streamId)}',
        );
      }
      throw StateError(
        'WebTransport session $_sessionId send credit exhausted: '
        'need $bytes bytes, have $_sessionSendCredit',
      );
    }
  }

  /// Records that [bytes] were received on the session (or [streamId]).
  ///
  /// Consumes receive credit and may signal that a window-update capsule should
  /// be sent to the peer. Returns the [WebTransportCapsule] to send when a
  /// window update is due, or `null` when no update is needed yet.
  ///
  /// Throws [StateError] if the incoming data would exceed the advertised
  /// receive limit (a protocol violation by the peer).
  WebTransportCapsule? onDataReceived(int bytes, {int? streamId}) {
    if (bytes < 0) {
      throw ArgumentError('bytes must be non-negative, got $bytes');
    }
    if (bytes == 0) return null;

    if (streamId != null) {
      final consumed = _streamReceiveConsumed[streamId] ?? 0;
      final limit = _streamReceiveCredit[streamId] ?? maxCredit;
      if (consumed + bytes > limit) {
        throw StateError(
          'WebTransport stream $streamId receive limit exceeded: '
          'peer sent ${consumed + bytes} bytes, limit is $limit',
        );
      }
      _streamReceiveConsumed[streamId] = consumed + bytes;
      return _maybeBuildStreamWindowUpdate(streamId);
    }

    if (_sessionReceiveConsumed + bytes > _sessionReceiveCredit) {
      throw StateError(
        'WebTransport session $_sessionId receive limit exceeded: '
        'peer sent ${_sessionReceiveConsumed + bytes} bytes, '
        'limit is $_sessionReceiveCredit',
      );
    }
    _sessionReceiveConsumed += bytes;
    return _maybeBuildSessionWindowUpdate();
  }

  WebTransportCapsule? _maybeBuildSessionWindowUpdate() {
    // Refresh the window once half of the advertised limit has been consumed.
    if (_sessionReceiveConsumed < _advertisedReceiveLimit ~/ 2) return null;
    _nextReceiveLimit =
        (_advertisedReceiveLimit * 2).clamp(0, maxCredit).toInt();
    final capsule = buildMaxDataCapsule(_nextReceiveLimit);
    _advertisedReceiveLimit = _nextReceiveLimit;
    _sessionReceiveCredit = _nextReceiveLimit;
    QuicLogger.log(
      'WebTransportFlowController($_sessionId): advertising session '
      'receive limit $_nextReceiveLimit',
    );
    return capsule;
  }

  WebTransportCapsule? _maybeBuildStreamWindowUpdate(int streamId) {
    final consumed = _streamReceiveConsumed[streamId]!;
    final advertised = _advertisedStreamReceiveLimit[streamId] ?? maxCredit;
    if (consumed < advertised ~/ 2) return null;
    final next = (advertised * 2).clamp(0, maxCredit).toInt();
    _advertisedStreamReceiveLimit[streamId] = next;
    _streamReceiveCredit[streamId] = next;
    QuicLogger.log(
      'WebTransportFlowController($_sessionId): advertising stream '
      '$streamId receive limit $next',
    );
    return buildMaxStreamDataCapsule(streamId, next);
  }

  /// Processes an incoming flow-control [capsule] and updates credit.
  ///
  /// Recognized capsule types are:
  /// - [CapsuleType.webtransportMaxData] — raises the session send credit.
  /// - [CapsuleType.webtransportMaxStreamData] — raises a stream's send credit.
  /// - [CapsuleType.drainCapabilities] — reduces the session send credit.
  ///
  /// Other capsule types are ignored. Returns `true` if the capsule was a
  /// recognized flow-control capsule and state was updated.
  bool processCapsule(WebTransportCapsule capsule) {
    switch (capsule.type) {
      case CapsuleType.webtransportMaxData:
        final newLimit = VarInt.decode(
          Uint8List.fromList(capsule.payload).buffer,
          offset: Uint8List.fromList(capsule.payload).offsetInBytes,
        );
        _applySessionSendLimit(newLimit);
        QuicLogger.log(
          'WebTransportFlowController($_sessionId): session send credit '
          'raised to $_sessionSendCredit',
        );
        return true;
      case CapsuleType.webtransportMaxStreamData:
        final bytes = Uint8List.fromList(capsule.payload);
        final streamId =
            VarInt.decode(bytes.buffer, offset: bytes.offsetInBytes);
        final limitOffset = bytes.offsetInBytes + VarInt.decodeLength(bytes[0]);
        final newLimit = VarInt.decode(bytes.buffer, offset: limitOffset);
        _applyStreamSendLimit(streamId, newLimit);
        QuicLogger.log(
          'WebTransportFlowController($_sessionId): stream $streamId send '
          'credit raised to ${availableStreamSendCredit(streamId)}',
        );
        return true;
      case CapsuleType.drainCapabilities:
        final newLimit = VarInt.decode(
          Uint8List.fromList(capsule.payload).buffer,
          offset: Uint8List.fromList(capsule.payload).offsetInBytes,
        );
        // Draining can only reduce credit, never raise it.
        _applySessionSendLimit(
          _sessionSendCredit < newLimit ? _sessionSendCredit : newLimit,
        );
        QuicLogger.log(
          'WebTransportFlowController($_sessionId): session send credit '
          'drained to $_sessionSendCredit',
        );
        return true;
      default:
        return false;
    }
  }

  void _applySessionSendLimit(int newLimit) {
    final clamped = newLimit.clamp(0, maxCredit).toInt();
    // A MAX_DATA grant only ever raises the budget; a drain only lowers it.
    if (clamped > _sessionSendCredit) {
      _sessionSendCredit = clamped;
    } else if (clamped < _sessionSendCredit) {
      _sessionSendCredit = clamped;
    }
  }

  void _applyStreamSendLimit(int streamId, int newLimit) {
    final clamped = newLimit.clamp(0, maxCredit).toInt();
    final current = _streamSendCredit[streamId] ?? maxCredit;
    if (clamped > current) {
      _streamSendCredit[streamId] = clamped;
    } else if (clamped < current) {
      _streamSendCredit[streamId] = clamped;
    }
  }

  /// Builds a `WEBTRANSPORT_MAX_DATA` capsule advertising [limit] bytes of
  /// session-level receive credit to the peer.
  ///
  /// The caller is responsible for sending the returned capsule on the
  /// session's control stream.
  WebTransportCapsule buildMaxDataCapsule(int limit) {
    final clamped = limit.clamp(0, maxCredit).toInt();
    return WebTransportCapsule(
      type: CapsuleType.webtransportMaxData,
      payload: VarInt.encode(clamped),
    );
  }

  /// Builds a `WEBTRANSPORT_MAX_STREAM_DATA` capsule advertising [limit] bytes
  /// of receive credit for [streamId].
  WebTransportCapsule buildMaxStreamDataCapsule(int streamId, int limit) {
    final clamped = limit.clamp(0, maxCredit).toInt();
    final builder = BytesBuilder();
    builder.add(VarInt.encode(streamId));
    builder.add(VarInt.encode(clamped));
    return WebTransportCapsule(
      type: CapsuleType.webtransportMaxStreamData,
      payload: builder.toBytes(),
    );
  }

  /// Builds a `DRAIN_CAPABILITIES` capsule requesting that the peer reduce its
  /// session-level send credit to [newCredit] bytes.
  ///
  /// Use this when the local receiver wants to throttle incoming data. The
  /// peer must not send more than [newCredit] bytes until a subsequent
  /// `WEBTRANSPORT_MAX_DATA` grant raises the limit.
  WebTransportCapsule buildDrainCapabilitiesCapsule(int newCredit) {
    final clamped = newCredit.clamp(0, maxCredit).toInt();
    return WebTransportCapsule(
      type: CapsuleType.drainCapabilities,
      payload: VarInt.encode(clamped),
    );
  }

  /// Resets all credit tracking to the supplied initial budgets.
  ///
  /// Useful when a session is reused or for testing.
  void reset({
    int? sessionSendCredit,
    int? sessionReceiveCredit,
  }) {
    _sessionSendCredit =
        (sessionSendCredit ?? maxCredit).clamp(0, maxCredit).toInt();
    _sessionReceiveCredit =
        (sessionReceiveCredit ?? maxCredit).clamp(0, maxCredit).toInt();
    _sessionReceiveConsumed = 0;
    _advertisedReceiveLimit = _sessionReceiveCredit;
    _nextReceiveLimit = _sessionReceiveCredit;
    _streamSendCredit.clear();
    _streamReceiveCredit.clear();
    _streamReceiveConsumed.clear();
    _advertisedStreamReceiveLimit.clear();
  }
}

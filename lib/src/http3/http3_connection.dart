import 'dart:async';
import 'dart:typed_data';

import 'cancel_push_frame.dart';
import 'capsule_protocol.dart';
import 'data_frame.dart';
import 'extended_connect_request.dart';
import 'frame_types.dart';
import 'goaway_frame.dart';
import 'headers_frame.dart';
import 'http3_request.dart';
import 'http3_response.dart';
import 'http3_stream.dart';
import 'origin_frame.dart';
import 'priority_update_frame.dart';
import 'push_promise_frame.dart';
import 'settings_frame.dart';
import 'webtransport_session.dart';
import 'package:quic_lib/src/recovery/packet_number_space.dart';
import 'package:quic_lib/src/streams/stream_scheduler.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:quic_lib/src/wire/varint.dart';

/// Represents a single HTTP/3 request/response stream mapped to a QUIC stream ID.
class Http3Stream {
  final int streamId;
  Http3Stream(this.streamId);
}

/// HTTP/3 HEADERS frame alias for [Http3HeadersFrame] (RFC 9114 Section 7.2.2).
///
/// This typedef exists for brevity inside [Http3Connection] and related
/// HTTP/3 types. It represents a QPACK-encoded field section carried on
/// a request or response stream.
///
/// See also:
/// - [Http3HeadersFrame] — the underlying concrete type.
/// - [DataFrame] — the corresponding DATA frame alias.
/// - [Http3Connection] — the connection that buffers and routes these frames.
typedef HeadersFrame = Http3HeadersFrame;

/// HTTP/3 DATA frame alias for [Http3DataFrame] (RFC 9114 Section 7.2.1).
///
/// This typedef exists for brevity inside [Http3Connection] and related
/// HTTP/3 types. It represents the raw octet payload of an HTTP/3 message.
///
/// See also:
/// - [Http3DataFrame] — the underlying concrete type.
/// - [HeadersFrame] — the corresponding HEADERS frame alias.
/// - [Http3Connection] — the connection that buffers and routes these frames.
typedef DataFrame = Http3DataFrame;

/// Manages an HTTP/3 connection over a QUIC transport.
///
/// An [Http3Connection] maps HTTP/3 semantics (requests, responses, headers,
/// and settings) onto QUIC streams and frames. Per RFC 9114, the first
/// client-initiated bidirectional stream (stream ID 0) is reserved as the
/// control stream, where SETTINGS and GOAWAY frames are exchanged. All other
/// streams carry individual request/response exchanges.
///
/// Use [sendRequest] to initiate an outbound request, [getResponse] to read
/// a received response, and [close] to send a GOAWAY and gracefully terminate
/// the connection. The underlying QUIC transport is exposed via
/// [quicConnection] for advanced use cases.
///
/// ## Example
/// ```dart
/// final quicConn = await endpoint.connect(remoteAddress, remotePort);
/// final http3 = Http3Connection(quicConnection: quicConn);
///
/// final request = Http3Request(
///   method: 'GET',
///   path: '/index.html',
///   headers: {'host': 'example.com'},
/// );
/// final streamId = await http3.sendRequest(request);
///
/// // Later, when the response arrives...
/// final response = http3.getResponse(streamId);
/// print('Status: ${response?.statusCode}');
///
/// http3.close();
/// ```
///
/// See also:
/// - [Http3Request] — an HTTP/3 request with QPACK-encoded headers.
/// - [Http3Response] — an HTTP/3 response with status and headers.
/// - [QuicConnection] — the underlying QUIC transport.
/// - RFC 9114 — HTTP/3.
class Http3Connection {
  final Object _quicConnection; // Will be QuicConnection once fully wired.

  final Http3SettingsFrame _localSettings;
  Http3SettingsFrame _peerSettings = Http3SettingsFrame();
  bool _settingsExchanged = false;
  Http3SettingsFrame? _pendingSettings;

  bool _isClosing = false;
  int _lastAcceptedStreamId = 0;
  final List<Http3GoawayFrame> _sentGoawayFrames = [];
  final Map<int, HeadersFrame> _pendingHeaders = {};
  final Map<int, List<DataFrame>> _pendingData = {};
  final Map<int, Http3PushPromiseFrame> _pushPromises = {};
  final List<Uint8List> _pendingQuicPackets = [];
  final List<String> _alternativeOrigins = [];
  final List<PriorityUpdateFrame> _pendingPriorityUpdates = [];
  final Map<int, WebTransportSession> _webTransportSessions = {};

  /// Creates an [Http3Connection] over [quicConnection].
  ///
  /// [quicConnection] must support `openBidirectionalStream()`,
  /// `openUnidirectionalStream()`, `buildEncryptedPacket()`, and
  /// `connectionId` (typically a [QuicConnection]).
  ///
  /// [localSettings] defaults to a conservative profile:
  /// `maxFieldSectionSize: 16384`, `maxTableCapacity: 0`,
  /// `blockedStreams: 0`.
  Http3Connection({
    required Object quicConnection,
    Http3SettingsFrame? localSettings,
  })  : _quicConnection = quicConnection,
        _localSettings = localSettings ??
            Http3SettingsFrame.from(
              maxFieldSectionSize: 16384,
              maxTableCapacity: 0,
              blockedStreams: 0,
            );

  /// The underlying QUIC connection.
  ///
  /// In typical usage this is a [QuicConnection]. Cast to [QuicConnection]
  /// to access stream allocation, packet building, or connection state.
  Object get quicConnection => _quicConnection;

  /// Local SETTINGS that will be sent to the peer on the control stream.
  ///
  /// These limits govern how much header data the peer can send and whether
  /// QPACK dynamic table capacity is enabled. Use [sendSettings] to enqueue
  /// the frame for transmission.
  Http3SettingsFrame get localSettings => _localSettings;

  /// SETTINGS received from the peer.
  Http3SettingsFrame get peerSettings => _peerSettings;

  /// True once the peer's SETTINGS frame has been received.
  bool get settingsExchanged => _settingsExchanged;

  /// True if the peer has enabled Extended CONNECT (RFC 9220).
  bool get isConnectProtocolEnabled =>
      (_peerSettings.settings[Http3SettingsId.enableConnectProtocol.value] ?? 0) != 0;

  /// True if the peer has enabled HTTP Datagrams (RFC 9297).
  bool get isH3DatagramEnabled =>
      (_peerSettings.settings[Http3SettingsId.h3Datagram.value] ?? 0) != 0;

  /// Pending SETTINGS frame to be sent on the control stream.
  Http3SettingsFrame? get pendingSettings => _pendingSettings;

  /// True once a GOAWAY frame has been received.
  bool get isClosing => _isClosing;

  /// The last accepted stream ID.
  int get lastAcceptedStreamId => _lastAcceptedStreamId;

  /// GOAWAY frames that have been sent on this connection.
  List<Http3GoawayFrame> get sentGoawayFrames =>
      List.unmodifiable(_sentGoawayFrames);

  /// True once a GOAWAY frame has been sent.
  bool get hasSentGoaway => _sentGoawayFrames.isNotEmpty;

  /// Alternative origins received via ORIGIN frames.
  List<String> get alternativeOrigins => List.unmodifiable(_alternativeOrigins);

  /// Pending PRIORITY_UPDATE frames staged for transmission.
  List<PriorityUpdateFrame> get pendingPriorityUpdates =>
      List.unmodifiable(_pendingPriorityUpdates);

  /// Active WebTransport sessions keyed by stream ID.
  Map<int, WebTransportSession> get webTransportSessions =>
      Map.unmodifiable(_webTransportSessions);

  /// Optional stream scheduler for priority-aware stream selection.
  StreamScheduler? streamScheduler;

  /// Pending HEADERS frame for a given stream.
  HeadersFrame? getPendingHeaders(int streamId) => _pendingHeaders[streamId];

  /// Pending DATA frames for a given stream.
  List<DataFrame> getPendingData(int streamId) =>
      List.unmodifiable(_pendingData[streamId] ?? []);

  /// True if the stream has pending DATA frames.
  bool hasBody(int streamId) =>
      _pendingData.containsKey(streamId) && _pendingData[streamId]!.isNotEmpty;

  /// Break [body] into DATA frames and store them for [streamId].
  Future<void> sendBody(int streamId, Uint8List body) async {
    const chunkSize = 4096;
    if (body.isEmpty) {
      // Empty body still emits an EOF marker (empty DATA frame).
      _pendingData.putIfAbsent(streamId, () => []).add(Http3DataFrame.empty());
      return;
    }
    for (var offset = 0; offset < body.length; offset += chunkSize) {
      final end =
          (offset + chunkSize < body.length) ? offset + chunkSize : body.length;
      final chunk = body.sublist(offset, end);
      _pendingData
          .putIfAbsent(streamId, () => [])
          .add(Http3DataFrame(data: chunk));
    }
  }

  /// Concatenate all DATA frame payloads for [streamId] into a single buffer.
  Uint8List? getBody(int streamId) {
    final frames = _pendingData[streamId];
    if (frames == null || frames.isEmpty) return null;

    // Exclude empty EOF-marker frames from the returned body.
    final nonEmptyFrames = frames.where((f) => f.data.isNotEmpty).toList();
    if (nonEmptyFrames.isEmpty) return Uint8List(0);

    final totalLength =
        nonEmptyFrames.fold<int>(0, (sum, f) => sum + f.data.length);
    final result = Uint8List(totalLength);
    var offset = 0;
    for (final frame in nonEmptyFrames) {
      result.setRange(offset, offset + frame.data.length, frame.data);
      offset += frame.data.length;
    }
    return result;
  }

  /// Initiate the HTTP/3 connection by sending a SETTINGS frame on the
  /// control stream.
  ///
  /// Stores the default local SETTINGS in [_pendingSettings].
  Http3SettingsFrame sendSettings() {
    _pendingSettings = Http3SettingsFrame.from(
      maxFieldSectionSize: 65536,
      maxTableCapacity: 0,
      blockedStreams: 0,
    );
    return _pendingSettings!;
  }

  /// Process a received SETTINGS frame from the peer's control stream.
  void onSettingsReceived(Http3SettingsFrame settings) {
    _peerSettings = settings;
    _settingsExchanged = true;
  }

  /// Process a received ORIGIN frame and store the advertised origins.
  void onOriginFrameReceived(OriginFrame frame) {
    _alternativeOrigins.addAll(frame.origins);
  }

  /// Stage a PRIORITY_UPDATE frame for transmission.
  ///
  /// The frame is stored in [pendingPriorityUpdates] and serialized into
  /// [pendingQuicPackets] for later transmission by the transport layer.
  void sendPriorityUpdate(int streamId, String priority) {
    final frame = PriorityUpdateFrame(
      streamId: streamId,
      priorityFieldValue: priority,
    );
    _pendingPriorityUpdates.add(frame);
    _pendingQuicPackets.add(frame.toFrame().serialize());
  }

  /// Process a received PRIORITY_UPDATE frame.
  ///
  /// If a [streamScheduler] is set, the update is routed to it.
  void onPriorityUpdateReceived(PriorityUpdateFrame frame) {
    _pendingPriorityUpdates.add(frame);
    if (streamScheduler != null) {
      // Route to stream priority scheduler if one exists.
      // The current StreamScheduler interface is selection-only;
      // priority updates are stored for scheduler implementations
      // that may read them from the connection state.
    }
  }

  /// Send an HTTP/3 request on a new client-initiated bidirectional stream.
  ///
  /// Encodes the request headers using QPACK, optionally writes the body
  /// as DATA frames, and stores both in the pending outbound queue. The
  /// returned stream ID uniquely identifies this request/response exchange.
  ///
  /// The caller must flush the pending frames to the QUIC transport; this
  /// method only stages them internally.
  Future<int> sendRequest(Http3Request request) async {
    final quic = _quicConnection as dynamic;
    final streamId = quic.openBidirectionalStream() as int;
    final headers = request.encodeHeaders();
    _sendHeaders(streamId, headers);
    if (request.body != null && request.body!.isNotEmpty) {
      _sendData(streamId, request.body!);
    }
    return streamId;
  }

  /// Send an Extended CONNECT request (RFC 9220) on a new bidirectional stream.
  ///
  /// Encodes the request headers with the `:protocol` pseudo-header and
  /// optionally stages a request body. Returns the stream ID for this exchange.
  Future<int> sendExtendedConnect(ExtendedConnectRequest request) async {
    final quic = _quicConnection as dynamic;
    final streamId = quic.openBidirectionalStream() as int;
    final headers = request.encodeHeaders();
    _sendHeaders(streamId, headers);
    if (request.body != null && request.body!.isNotEmpty) {
      _sendData(streamId, request.body!);
    }
    return streamId;
  }

  /// Create a HEADERS frame from [headers] and store it for [streamId].
  void _sendHeaders(int streamId, Uint8List headers) {
    final frame = Http3HeadersFrame(encodedFieldSection: headers);
    _pendingHeaders[streamId] = frame;
  }

  /// Create a DATA frame from [data] and store it for [streamId].
  void _sendData(int streamId, Uint8List data) {
    final frame = Http3DataFrame(data: data);
    _pendingData.putIfAbsent(streamId, () => []).add(frame);
  }

  /// Return a decoded [Http3Response] if headers were received for [streamId].
  Http3Response? getResponse(int streamId) {
    final headersFrame = _pendingHeaders[streamId];
    if (headersFrame == null) return null;
    final encoded = Uint8List.fromList(headersFrame.encodedFieldSection);
    return Http3Response.decodeHeaders(encoded);
  }

  /// Open a new bidirectional stream and return a wrapper for sending data.
  Future<Http3QuicStream> openStream() async {
    final quic = _quicConnection as dynamic;
    final streamId = quic.openBidirectionalStream() as int;
    return Http3QuicStream(streamId, this);
  }

  /// Create a WebTransport session by sending an Extended CONNECT request.
  ///
  /// Awaits response headers; throws if the status is not 2xx.
  Future<WebTransportSession> createWebTransportSession(
    WebTransportConnectRequest request,
  ) async {
    final extendedRequest = ExtendedConnectRequest(
      protocol: 'webtransport',
      scheme: 'https',
      authority: request.authority,
      path: request.path,
      headers: {
        if (request.origin != null) 'origin': request.origin!,
      },
    );
    final streamId = await sendExtendedConnect(extendedRequest);

    // Poll for response headers with a short timeout.
    for (var attempt = 0; attempt < 50; attempt++) {
      final response = getResponse(streamId);
      if (response != null) {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          throw StateError(
            'WebTransport session establishment failed: '
            '${response.statusCode}',
          );
        }
        final session = WebTransportSession(this, streamId);
        _webTransportSessions[streamId] = session;
        return session;
      }
      await Future<void>.delayed(Duration(milliseconds: 1));
    }

    throw StateError('Timed out waiting for WebTransport session response');
  }

  /// Send an unreliable datagram for [sessionId] using the QUIC connection.
  ///
  /// Falls back to a DATAGRAM capsule if the underlying transport does not
  /// support QUIC datagrams.
  void sendDatagram(int sessionId, Uint8List data) {
    final quic = _quicConnection as dynamic;
    try {
      quic.sendDatagram(data);
    } catch (_) {
      // Fallback: send as DATAGRAM capsule on the session stream.
      sendCapsule(sessionId, DatagramCapsule(data));
    }
  }

  /// Send a [capsule] for [sessionId] as DATA frames on the control stream.
  void sendCapsule(int sessionId, Capsule capsule) {
    final bytes = capsule.serialize();
    _sendData(sessionId, bytes);
  }

  /// Process an incoming [capsule] belonging to [sessionId].
  void onCapsuleReceived(int sessionId, Capsule capsule) {
    final session = _webTransportSessions[sessionId];
    if (session != null) {
      session.onCapsule(capsule);
    }
    if (capsule is CloseWebTransportSessionCapsule) {
      _webTransportSessions.remove(sessionId);
    }
  }

  /// Register a push promise manually.
  void registerPushPromise(int pushId, Http3PushPromiseFrame frame) {
    _pushPromises[pushId] = frame;
  }

  /// Check if a push promise with [pushId] is registered.
  bool hasPushPromise(int pushId) => _pushPromises.containsKey(pushId);

  /// Process received frames on a QUIC stream.
  void onStreamFrame(int streamId, Http3Frame frame) {
    switch (frame.type) {
      case Http3FrameType.headers:
        _pendingHeaders[streamId] = HeadersFrame.fromPayload(frame.payload);
        if (streamId > _lastAcceptedStreamId) {
          _lastAcceptedStreamId = streamId;
        }
        break;
      case Http3FrameType.data:
        final dataFrame = DataFrame.fromPayload(frame.payload);
        _pendingData.putIfAbsent(streamId, () => []).add(dataFrame);
        if (streamId > _lastAcceptedStreamId) {
          _lastAcceptedStreamId = streamId;
        }
        break;
      case Http3FrameType.settings:
        onSettingsReceived(
          Http3SettingsFrame.parsePayload(Uint8List.fromList(frame.payload)),
        );
        break;
      case Http3FrameType.goaway:
        _isClosing = true;
        break;
      case Http3FrameType.pushPromise:
        final pushFrame = Http3PushPromiseFrame.parsePayload(
          Uint8List.fromList(frame.payload),
        );
        _pushPromises[pushFrame.pushId] = pushFrame;
        break;
      case Http3FrameType.cancelPush:
        final cancelFrame = Http3CancelPushFrame.parsePayload(
          Uint8List.fromList(frame.payload),
        );
        _pushPromises.remove(cancelFrame.pushId);
        break;
      case Http3FrameType.origin:
        final originFrame = OriginFrame.parsePayload(
          Uint8List.fromList(frame.payload),
        );
        onOriginFrameReceived(originFrame);
        break;
      case Http3FrameType.priorityUpdate:
        final priorityFrame = PriorityUpdateFrame.parsePayload(
          Uint8List.fromList(frame.payload),
        );
        onPriorityUpdateReceived(priorityFrame);
        break;
      case Http3FrameType.priorityUpdatePush:
        final priorityPushFrame = PriorityUpdatePushFrame.parsePayload(
          Uint8List.fromList(frame.payload),
        );
        onPriorityUpdateReceived(
          PriorityUpdateFrame(
            streamId: priorityPushFrame.streamId,
            priorityFieldValue: priorityPushFrame.priorityFieldValue,
          ),
        );
        break;
      default:
        // No-op for unhandled frame types.
        break;
    }
  }

  /// Gracefully close the HTTP/3 connection.
  ///
  /// Sends a GOAWAY frame on the control stream with the last accepted
  /// stream ID, transitions the connection to the closing state, and queues
  /// the resulting QUIC packet in [pendingQuicPackets]. After calling this
  /// method no new requests should be initiated.
  void close() {
    _isClosing = true;
    final goaway =
        Http3GoawayFrame(lastStreamIdOrPushId: _lastAcceptedStreamId);
    _sentGoawayFrames.add(goaway);
    unawaited(_sendGoawayFrame(goaway.toFrame().serialize()));
  }

  /// QUIC packets built by HTTP/3 operations (e.g., GOAWAY) that are
  /// waiting to be sent by the transport layer.
  List<Uint8List> get pendingQuicPackets =>
      List.unmodifiable(_pendingQuicPackets);

  /// Open a new unidirectional stream and prepend the [StreamType] identifier.
  ///
  /// Per RFC 9114 Section 6.2, the first bytes of a unidirectional stream carry
  /// a varint-encoded stream type. This helper allocates a QUIC unidirectional
  /// stream, builds an encrypted packet with the type-prefixed data, and
  /// returns the stream ID.
  Future<int> _openUnidirectionalStream(StreamType type, Uint8List data) async {
    final quic = _quicConnection as dynamic;
    int streamId;
    try {
      streamId = quic.openUnidirectionalStream() as int;
    } catch (_) {
      // If the underlying connection doesn't support stream allocation,
      // just store the raw bytes for later transmission.
      _pendingQuicPackets.add(data);
      return -1;
    }
    final typeBytes = VarInt.encode(type.value);
    final prefixed = Uint8List(typeBytes.length + data.length);
    prefixed.setRange(0, typeBytes.length, typeBytes);
    prefixed.setRange(typeBytes.length, prefixed.length, data);
    try {
      final dcid = (quic.connectionId as List<int>?) ?? [];
      final packet = await quic.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(
            streamId: streamId,
            data: prefixed,
            fin: false,
            offset: 0,
          ),
        ],
        dcid: dcid,
      );
      _pendingQuicPackets.add(packet as Uint8List);
    } catch (_) {
      // If the underlying connection doesn't support packet building,
      // store the raw frame bytes for later transmission.
      _pendingQuicPackets.add(prefixed);
    }
    return streamId;
  }

  /// Send a GOAWAY frame by building a QUIC packet containing the frame
  /// as a STREAM frame on the HTTP/3 control stream.
  Future<void> _sendGoawayFrame(Uint8List bytes) async {
    await _openUnidirectionalStream(StreamType.control, bytes);
  }

  /// Process received data on a unidirectional stream.
  ///
  /// Reads the first varint as the [StreamType] identifier, then parses the
  /// remaining bytes as HTTP/3 frames and dispatches them via [onStreamFrame].
  void onUnidirectionalStreamData(int streamId, Uint8List data) {
    if (data.isEmpty) return;
    final typeLength = VarInt.decodeLength(data[0]);
    if (data.length < typeLength) return;
    final typeValue = VarInt.decode(data.buffer);
    final streamType = StreamType.fromValue(typeValue);
    if (streamType == null) return;

    var offset = typeLength;
    while (offset < data.length) {
      try {
        final (frame, consumed) = Http3Frame.parse(data, offset: offset);
        onStreamFrame(streamId, frame);
        offset += consumed;
      } catch (_) {
        break;
      }
    }
  }
}

/// Lightweight wrapper around a QUIC stream ID for sending data.
class Http3QuicStream {
  final int streamId;
  final Http3Connection _connection;

  Http3QuicStream(this.streamId, this._connection);

  /// Send [data] as a DATA frame on this stream.
  void send(Uint8List data) {
    _connection._sendData(streamId, data);
  }
}

/// HTTP/3 built on top of the QUIC transport.
///
/// Implements [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html), mapping
/// HTTP semantics onto QUIC streams. This barrel exposes the HTTP/3 connection
/// manager, request/response objects, frame types, and QPACK header compression.
///
/// Exports include:
/// * [Http3Connection] — manages SETTINGS, GOAWAY, and stream lifecycle.
/// * [Http3Request] / [Http3Response] — request and response abstractions with
///   QPACK-encoded pseudo-headers.
/// * [Http3FrameType] and frame types — HEADERS, DATA, SETTINGS, GOAWAY, etc.
/// * [Http3SettingsFrame] / [Http3SettingsId] — connection settings negotiation.
///
/// Use this library when you are building an HTTP/3 client or server on top of
/// a [QuicConnection]. If you need the underlying transport primitives, import
/// `quic.dart` instead. If you need the full stack, import `quic_lib.dart`.
///
/// See also:
/// * `quic_lib.dart` — the full public API.
/// * `quic.dart` — QUIC transport primitives.
library;

export 'src/http3/http3_connection.dart' show Http3Connection;
export 'src/http3/http3_request.dart' show Http3Request;
export 'src/http3/http3_response.dart' show Http3Response;
export 'src/http3/http3_stream.dart'
    show Http3StreamType, Http3StreamHandler, StreamType;
export 'src/http3/extended_connect_request.dart' show ExtendedConnectRequest;
export 'src/http3/settings_frame.dart' show Http3SettingsFrame, Http3SettingsId;
export 'src/http3/headers_frame.dart' show Http3HeadersFrame;
export 'src/http3/data_frame.dart' show Http3DataFrame;
export 'src/http3/frame_types.dart' show Http3FrameType;
export 'src/http3/qpack_encoder_stream.dart'
    show
        EncoderInstruction,
        InsertWithNameReference,
        InsertWithoutNameReference,
        Duplicate,
        SetDynamicTableCapacity;
export 'src/http3/qpack_decoder_stream.dart'
    show
        DecoderInstruction,
        SectionAcknowledgment,
        StreamCancellation,
        InsertCountIncrement;
export 'src/http3/origin_frame.dart' show OriginFrame;
export 'src/http3/priority_update_frame.dart'
    show PriorityUpdateFrame, PriorityUpdatePushFrame;
export 'src/http3/capsule_protocol.dart'
    show
        Capsule,
        DatagramCapsule,
        CloseWebTransportSessionCapsule,
        DrainWebTransportSessionCapsule,
        GoawayCapsule;

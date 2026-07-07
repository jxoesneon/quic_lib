import 'dart:typed_data';

import 'package:quic_lib/http3.dart';
import 'package:quic_lib/quic_lib.dart';
import 'package:test/test.dart';

/// Fixed destination connection ID used by both endpoints.
const List<int> _testDcid = <int>[
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x07,
];

/// Build a [QuicConnection] with deterministic application-space keys.
QuicConnection _createTestConnection(
    HandshakeRole role, KeyManager keyManager) {
  final conn = QuicConnection(
    stateMachine: ConnectionStateMachine(),
    cidManager: ConnectionIdManager(),
    pnSpaceManager: PacketNumberSpaceManager(),
    rttEstimator: RttEstimator(),
    lossDetector: LossDetector(),
    ptoScheduler: PtoScheduler(RttEstimator()),
    congestionController: CongestionController(),
    streamIdAllocator: StreamIdAllocator(),
    keyManager: keyManager,
    handshakeMachine: HandshakeStateMachine(role),
  );
  conn.stateMachine
    ..transitionTo(ConnectionState.handshaking, reason: 'test')
    ..transitionTo(ConnectionState.established, reason: 'test');
  conn.onBytesReceived(10000);
  return conn;
}

/// Parse concatenated HTTP/3 frames from a byte payload.
List<Http3Frame> _parseHttp3Frames(Uint8List payload) {
  final frames = <Http3Frame>[];
  var offset = 0;
  while (offset < payload.length) {
    final (frame, consumed) = Http3Frame.parse(payload, offset: offset);
    frames.add(frame);
    offset += consumed;
  }
  return frames;
}

/// Serialize the pending HEADERS and DATA frames for [streamId].
Uint8List _serializeHttp3Message(Http3Connection conn, int streamId) {
  final builder = BytesBuilder();
  final headers = conn.getPendingHeaders(streamId);
  if (headers == null) {
    throw StateError('No pending HEADERS frame for stream $streamId');
  }
  builder.add(headers.toFrame().serialize());
  for (final dataFrame in conn.getPendingData(streamId)) {
    builder.add(dataFrame.toFrame().serialize());
  }
  return builder.toBytes();
}

void main() {
  group('E2E HTTP/3 over encrypted QUIC', () {
    test('encrypted QUIC packet carries HTTP/3 request and response', () async {
      final backend = DefaultCryptoBackend();

      final clientKm = await KeyManager.forTestWithKeys(
        role: HandshakeRole.client,
        backend: backend,
      );
      final serverKm = await KeyManager.forTestWithKeys(
        role: HandshakeRole.server,
        backend: backend,
      );

      final client = _createTestConnection(HandshakeRole.client, clientKm);
      final server = _createTestConnection(HandshakeRole.server, serverKm);

      // === Client builds an HTTP/3 GET request ===
      final clientHttp3 = Http3Connection(quicConnection: client);
      final streamId = await clientHttp3.sendRequest(
        Http3Request(
          method: 'GET',
          path: '/hello',
          headers: {'host': 'example.com'},
        ),
      );
      expect(streamId, equals(0));

      final requestPayload = _serializeHttp3Message(clientHttp3, streamId);
      expect(requestPayload, isNotEmpty);

      // Encrypt the HTTP/3 payload inside a QUIC STREAM frame.
      final encryptedRequest = await client.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(
            streamId: streamId,
            data: requestPayload,
            fin: false,
            offset: 0,
          ),
        ],
        dcid: _testDcid,
      );
      expect(encryptedRequest.length, greaterThan(0));

      // === Server decrypts the request ===
      final processed = await server.processEncryptedDatagram(encryptedRequest);
      expect(processed, equals(1));

      // The STREAM frame should have created a receive stream on the server.
      expect(server.streamManager.getStream(streamId), isNotNull);

      // Parse the HTTP/3 frames from the request payload (the same bytes that
      // were carried inside the encrypted QUIC STREAM frame).
      final requestFrames = _parseHttp3Frames(requestPayload);
      expect(requestFrames.length, greaterThanOrEqualTo(1));
      expect(requestFrames.first.type, equals(Http3FrameType.headers));

      // Feed the frames into a server-side Http3Connection.
      final serverHttp3 = Http3Connection(quicConnection: server);
      for (final frame in requestFrames) {
        serverHttp3.onStreamFrame(streamId, frame);
      }

      // Verify the request was decoded correctly.
      final receivedHeaders = serverHttp3.getPendingHeaders(streamId);
      expect(receivedHeaders, isNotNull);
      final request = Http3Request.decodeHeaders(
        Uint8List.fromList(receivedHeaders!.encodedFieldSection),
      );
      expect(request.method, equals('GET'));
      expect(request.path, equals('/hello'));

      // === Server builds a 200 OK response ===
      // Use stream ID 1 (server bidirectional) for the response to avoid
      // conflicting with the client's send stream at ID 0.
      const responseStreamId = 1;
      serverHttp3.sendResponse(
        responseStreamId,
        Http3Response(
          statusCode: 200,
          headers: {'content-type': 'text/plain'},
        ),
      );
      await serverHttp3.sendBody(
        responseStreamId,
        Uint8List.fromList('Hello, HTTP/3!'.codeUnits),
      );

      final responsePayload =
          _serializeHttp3Message(serverHttp3, responseStreamId);
      expect(responsePayload, isNotEmpty);

      // Encrypt the response STREAM frame.
      final encryptedResponse = await server.buildEncryptedPacket(
        space: PacketNumberSpace.application,
        frames: [
          StreamFrame(
            streamId: responseStreamId,
            data: responsePayload,
            fin: false,
            offset: 0,
          ),
        ],
        dcid: _testDcid,
      );
      expect(encryptedResponse.length, greaterThan(0));

      // === Client decrypts the response ===
      final clientProcessed =
          await client.processEncryptedDatagram(encryptedResponse);
      expect(clientProcessed, equals(1));

      // The response STREAM frame should have created a receive stream on the
      // client at stream ID 1.
      expect(client.streamManager.getStream(responseStreamId), isNotNull);

      // Parse the response HTTP/3 frames.
      final responseFrames = _parseHttp3Frames(responsePayload);
      expect(responseFrames.length, greaterThanOrEqualTo(2));
      expect(responseFrames.first.type, equals(Http3FrameType.headers));

      // Feed the response frames into the client's HTTP/3 connection.
      for (final frame in responseFrames) {
        clientHttp3.onStreamFrame(responseStreamId, frame);
      }

      // Verify the response.
      final response = clientHttp3.getResponse(responseStreamId);
      expect(response, isNotNull);
      expect(response!.statusCode, equals(200));
      expect(response.headers['content-type'], equals('text/plain'));

      final body = clientHttp3.getBody(responseStreamId);
      expect(body, isNotNull);
      expect(String.fromCharCodes(body!), equals('Hello, HTTP/3!'));

      client.abort();
      server.abort();
    });
  });
}

# API Surface Architecture

**Version**: 1.0-draft  
**Status**: Architecture  
**Subsystem**: Class-Level Design

---

## 1. Purpose

This document describes the class-level architecture for `dart_quic`: the public API classes, their relationships, and how they map to the underlying QUIC protocol concepts.

---

## 2. Class Hierarchy

```
dart_quic (package)
│
├── quic.dart (core QUIC)
│   ├── QuicEndpoint
│   ├── QuicConnection
│   ├── QuicStream
│   ├── QuicSendStream
│   ├── QuicReceiveStream
│   ├── QuicConfiguration
│   ├── QuicConnectionStats
│   └── QuicException (hierarchy)
│
├── http3.dart (HTTP/3)
│   ├── Http3Client
│   ├── Http3Server
│   ├── Http3Request
│   ├── Http3Response
│   ├── Http3Settings
│   └── Http3Exception
│
├── webtransport.dart (WebTransport)
│   ├── WebTransportClient
│   ├── WebTransportServer
│   ├── WebTransportSession
│   ├── WebTransportBidiStream
│   ├── WebTransportSendStream
│   ├── WebTransportReceiveStream
│   └── WebTransportCloseInfo
│
└── libp2p.dart (libp2p adapter)
    ├── Libp2pQuicTransport
    ├── Libp2pQuicListener
    ├── Libp2pConnection
    ├── Libp2pStream
    ├── PeerId
    └── Multiaddr
```

---

## 3. Core QUIC Classes

### 3.1 QuicEndpoint

The top-level entry point. Manages a UDP socket and can both listen for and initiate connections.

```dart
abstract class QuicEndpoint {
  // Factory
  static Future<QuicEndpoint> bind(
    InternetAddress address,
    int port, {
    SecurityContext? securityContext,
    QuicConfiguration? configuration,
  });
  
  // Properties
  InternetAddress get address;
  int get port;
  
  // Client operations
  Future<QuicConnection> connect(
    InternetAddress remoteAddress,
    int remotePort, {
    String? serverName,
    List<String>? alpnProtocols,
  });
  
  // Server operations
  Stream<QuicConnection> get connections;
  
  // Lifecycle
  Future<void> close();
}
```

**Rationale**: Combines client and server in one class because QUIC uses the same UDP socket for both roles. This mirrors `RawDatagramSocket`'s bidirectional nature.

### 3.2 QuicConnection

Represents an established QUIC connection.

```dart
abstract class QuicConnection {
  // Identity
  List<int> get localConnectionId;
  List<int> get remoteConnectionId;
  InternetAddress get remoteAddress;
  int get remotePort;
  String? get alpnProtocol;
  
  // Streams
  Future<QuicStream> openBidirectionalStream();
  Future<QuicSendStream> openUnidirectionalStream();
  Stream<QuicStream> get incomingBidirectionalStreams;
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams;
  
  // Datagrams (RFC 9221)
  void sendDatagram(List<int> data);
  Stream<List<int>> get datagrams;
  
  // Lifecycle
  Future<void> close({int errorCode = 0, String? reason});
  Future<QuicCloseInfo> get closed;
  
  // Diagnostics
  QuicConnectionStats get stats;
}
```

**Rationale**: Follows the pattern of `dart:io` `Socket`/`SecureSocket`. Streams are exposed as Dart `Stream<QuicStream>` for natural async consumption.

### 3.3 QuicStream

A bidirectional QUIC stream — both readable and writable.

```dart
abstract class QuicStream implements QuicSendStream, QuicReceiveStream {
  int get streamId;
  bool get isLocallyInitiated;
}
```

### 3.4 QuicSendStream / QuicReceiveStream

```dart
abstract class QuicSendStream {
  int get streamId;
  void add(List<int> data);
  Future<void> close();          // send FIN
  Future<void> reset(int errorCode);
  Future<void> get done;         // all data ACKed
}

abstract class QuicReceiveStream {
  int get streamId;
  Stream<List<int>> get stream;   // ordered bytes
  Future<void> stopSending(int errorCode);
}
```

**Rationale**: Separate interfaces allow unidirectional streams to expose only the relevant half. `QuicStream` implements both for bidirectional.

---

## 4. HTTP/3 Classes

### 4.1 Http3Client

```dart
abstract class Http3Client {
  static Future<Http3Client> connect(Uri uri, {
    Http3Settings? settings,
    SecurityContext? securityContext,
  });
  
  Future<Http3Response> send(Http3Request request);
  Future<Http3Response> get(Uri uri, {Map<String, String>? headers});
  Future<Http3Response> post(Uri uri, {
    Map<String, String>? headers,
    Object? body,  // String, List<int>, or Stream<List<int>>
  });
  
  Stream<Http3PushResponse> get serverPushes;
  Future<void> close();
}
```

### 4.2 Http3Server

```dart
abstract class Http3Server {
  static Future<Http3Server> bind(
    InternetAddress address,
    int port, {
    required SecurityContext securityContext,
    Http3Settings? settings,
  });
  
  Stream<Http3ServerRequest> get requests;
  Future<void> close();
}

abstract class Http3ServerRequest {
  String get method;
  Uri get uri;
  Map<String, List<String>> get headers;
  Stream<List<int>> get body;
  
  Http3ServerResponse get response;
}

abstract class Http3ServerResponse {
  int statusCode;
  Map<String, String> headers;
  void add(List<int> data);
  Future<void> close();
}
```

**Rationale**: Follows `dart:io` `HttpServer` and `HttpClient` patterns for familiarity.

---

## 5. WebTransport Classes

### 5.1 Session

```dart
abstract class WebTransportSession {
  int get sessionId;
  
  // Streams
  Future<WebTransportBidiStream> openBidirectionalStream();
  Stream<WebTransportBidiStream> get incomingBidirectionalStreams;
  Future<WebTransportSendStream> openUnidirectionalStream();
  Stream<WebTransportReceiveStream> get incomingUnidirectionalStreams;
  
  // Datagrams
  void sendDatagram(List<int> data);
  Stream<List<int>> get datagrams;
  int get maxDatagramSize;
  
  // Lifecycle
  Future<void> close({int errorCode = 0, String reason = ''});
  Future<void> get closed;
  WebTransportCloseInfo? get closeInfo;
}
```

---

## 6. libp2p Classes

### 6.1 Transport

```dart
abstract class Libp2pQuicTransport {
  Future<Libp2pConnection> dial(Multiaddr target, {
    required PrivateKey hostKey,
    PeerId? expectedPeerId,
  });
  
  Future<Libp2pQuicListener> listen(Multiaddr bindAddr, {
    required PrivateKey hostKey,
  });
}
```

### 6.2 PeerId

```dart
class PeerId {
  final List<int> bytes;  // multihash bytes
  
  factory PeerId.fromPublicKey(PublicKey key);
  factory PeerId.fromBytes(List<int> bytes);
  factory PeerId.fromBase58(String encoded);
  factory PeerId.fromCid(String cid);
  
  String toBase58();
  String toCid();
  
  @override
  bool operator ==(Object other);
  
  @override
  int get hashCode;
}
```

### 6.3 Multiaddr

```dart
class Multiaddr {
  final List<MultiaddrComponent> components;
  
  factory Multiaddr.parse(String str);
  factory Multiaddr.fromBytes(List<int> bytes);
  
  InternetAddress? get ip;
  int? get port;
  PeerId? get peerId;
  bool get isQuicV1;
  
  String encode();
  List<int> toBytes();
}
```

---

## 7. Configuration Classes

### 7.1 QuicConfiguration

```dart
class QuicConfiguration {
  final Duration maxIdleTimeout;
  final int initialMaxData;
  final int initialMaxStreamDataBidiLocal;
  final int initialMaxStreamDataBidiRemote;
  final int initialMaxStreamDataUni;
  final int initialMaxStreamsBidi;
  final int initialMaxStreamsUni;
  final int maxUdpPayloadSize;
  final bool enableDatagrams;
  final int maxDatagramFrameSize;
  final bool enableMigration;
  final CongestionAlgorithm congestionAlgorithm;
  final Duration? handshakeTimeout;
  
  const QuicConfiguration({ /* defaults */ });
  
  QuicConfiguration copyWith({ /* all fields optional */ });
}
```

### 7.2 Http3Settings

```dart
class Http3Settings {
  final int qpackMaxTableCapacity;
  final int qpackBlockedStreams;
  final int? maxFieldSectionSize;
  final bool enableServerPush;
  
  const Http3Settings({ /* defaults */ });
}
```

---

## 8. Exception Hierarchy

```
QuicException (abstract)
├── QuicConnectionException
│   ├── isApplicationError: bool
│   ├── errorCode: int
│   └── reason: String?
├── QuicStreamException
│   ├── streamId: int
│   └── errorCode: int
├── QuicHandshakeException
│   └── tlsAlertDescription: String?
├── QuicTimeoutException
└── QuicVersionNegotiationException
    └── supportedVersions: List<int>

Http3Exception extends QuicException
├── Http3ProtocolException
│   └── h3ErrorCode: int
└── Http3StreamException

WebTransportException extends QuicException
└── sessionId: int
```

---

## 9. Relationship Diagram

```
QuicEndpoint ─── creates ──→ QuicConnection
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
            QuicStream    QuicSendStream   QuicReceiveStream
                    │
          ┌─────────┴──────────┐
          │                    │
          ▼                    ▼
   Http3Connection     Libp2pConnection
          │                    │
          ▼                    ▼
Http3Client/Server    Libp2pQuicTransport
          │
          ▼
WebTransportSession
```

---

## 10. Usage Examples

### 10.1 QUIC Echo Server

```dart
final endpoint = await QuicEndpoint.bind(
  InternetAddress.anyIPv4, 4433,
  securityContext: serverCtx,
);

await for (final connection in endpoint.connections) {
  connection.incomingBidirectionalStreams.listen((stream) async {
    await for (final data in stream.stream) {
      stream.add(data);  // echo back
    }
    await stream.close();
  });
}
```

### 10.2 HTTP/3 Client

```dart
final client = await Http3Client.connect(Uri.parse('https://example.com'));
final response = await client.get(Uri.parse('https://example.com/api/data'));
print('Status: ${response.statusCode}');
await for (final chunk in response.body) {
  print(utf8.decode(chunk));
}
await client.close();
```

### 10.3 WebTransport Session

```dart
final session = await WebTransportClient.connect(
  Uri.parse('https://server.example.com/game'),
);

// Send datagrams (unreliable, low latency)
session.sendDatagram(positionUpdate.toBytes());

// Open reliable stream for chat
final chatStream = await session.openBidirectionalStream();
chatStream.outbound.add(utf8.encode('Hello!'));

// Receive datagrams
session.datagrams.listen((data) {
  handlePositionUpdate(data);
});
```

### 10.4 libp2p Connection

```dart
final transport = Libp2pQuicTransport();
final connection = await transport.dial(
  Multiaddr.parse('/ip4/192.168.1.1/udp/4001/quic-v1/p2p/QmPeer...'),
  hostKey: myPrivateKey,
);

final stream = await connection.openStream('/ipfs/bitswap/1.2.0');
stream.outbound.add(wantListMessage);
await for (final block in stream.inbound) {
  processBlock(block);
}
```

---

## 11. Design Decisions

| Decision | Rationale |
|----------|-----------|
| Single `QuicEndpoint` for client + server | QUIC uses one UDP socket for both; simplifies API |
| `Stream<List<int>>` for receive | Dart-idiomatic; backpressure via StreamSubscription.pause() |
| `void add()` for send (not Future) | Non-blocking write; buffered internally; `done` signals completion |
| Abstract classes (not concrete) | Allows mock implementations for testing |
| Separate http3/webtransport/libp2p exports | Users import only what they need |
| Configuration via immutable value class | Thread-safe; copyWith() for modification |
| Exceptions (not error codes) | Dart convention; enables try/catch patterns |

---

## References

- DART_API_SPEC.md (full API specification with all fields)
- MODULE_OVERVIEW.md (internal module architecture)
- Dart IO Library API: https://api.dart.dev/stable/dart-io/dart-io-library.html
- Effective Dart API Design: https://dart.dev/effective-dart/design

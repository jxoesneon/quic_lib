# Dart API Surface Specification

**Version**: 1.0-draft  
**Status**: Specification  
**Subsystem**: Public API Design

---

## 1. Purpose

This document specifies the public API surface for `dart_quic`: class hierarchy, `Stream`/`Future` idioms, `dart:io` integration patterns, error handling, and the zero-native-dependency constraint.

---

## 2. Design Principles

1. **Idiomatic Dart**: Follow `dart:io` conventions for networking APIs (`bind`, `connect`, streams, sinks).
2. **Layered exposure**: Users can operate at QUIC, HTTP/3, WebTransport, or libp2p levels.
3. **Zero native dependencies**: Core transport has no `dart:ffi` imports.
4. **Async-first**: All I/O operations return `Future` or expose `Stream`.
5. **Type-safe**: Leverage Dart's type system; no `dynamic` in public APIs.
6. **Testable**: All I/O goes through abstract interfaces for mocking.

---

## 3. Package Structure

```
dart_quic/
├── lib/
│   ├── quic.dart              // Core QUIC transport (public)
│   ├── http3.dart             // HTTP/3 layer (public)
│   ├── webtransport.dart      // WebTransport layer (public)
│   ├── libp2p.dart            // libp2p adapter (public)
│   └── src/
│       ├── wire/              // Packet encoding/decoding
│       ├── crypto/            // TLS, AEAD, key derivation
│       ├── streams/           // Stream multiplexing, flow control
│       ├── recovery/          // Loss detection, congestion control
│       ├── http3/             // HTTP/3 frames, QPACK
│       ├── webtransport/      // WebTransport session management
│       └── libp2p/            // Peer auth, multiaddr, multistream
```

---

## 4. Core QUIC API

### 4.1 Connection Establishment

```dart
/// A QUIC endpoint that can listen for and initiate connections.
abstract class QuicEndpoint {
  /// Bind to a local address and port for both listening and dialing.
  static Future<QuicEndpoint> bind(
    InternetAddress address,
    int port, {
    SecurityContext? securityContext,
    QuicConfiguration? configuration,
  });
  
  /// The local address this endpoint is bound to.
  InternetAddress get address;
  int get port;
  
  /// Connect to a remote QUIC server.
  Future<QuicConnection> connect(
    InternetAddress remoteAddress,
    int remotePort, {
    String? serverName,  // SNI
    List<String>? alpnProtocols,
  });
  
  /// Accept incoming connections (server mode).
  Stream<QuicConnection> get connections;
  
  /// Close the endpoint and all connections.
  Future<void> close();
}
```

### 4.2 Connection

```dart
/// An established QUIC connection.
abstract class QuicConnection {
  /// Connection identifiers
  List<int> get localConnectionId;
  List<int> get remoteConnectionId;
  
  /// Remote address
  InternetAddress get remoteAddress;
  int get remotePort;
  
  /// Negotiated ALPN protocol
  String? get alpnProtocol;
  
  /// Open a new bidirectional stream.
  Future<QuicStream> openBidirectionalStream();
  
  /// Open a new unidirectional (send-only) stream.
  Future<QuicSendStream> openUnidirectionalStream();
  
  /// Incoming bidirectional streams opened by the peer.
  Stream<QuicStream> get incomingBidirectionalStreams;
  
  /// Incoming unidirectional streams from the peer (receive-only).
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams;
  
  /// Send an unreliable datagram (RFC 9221).
  void sendDatagram(List<int> data);
  
  /// Receive datagrams from the peer.
  Stream<List<int>> get datagrams;
  
  /// Close the connection gracefully.
  Future<void> close({int errorCode = 0, String? reason});
  
  /// Completes when the connection is closed (by either side).
  Future<QuicCloseInfo> get closed;
  
  /// Connection statistics.
  QuicConnectionStats get stats;
}
```

### 4.3 Streams

```dart
/// A bidirectional QUIC stream.
abstract class QuicStream implements QuicSendStream, QuicReceiveStream {
  int get streamId;
}

/// A send-only QUIC stream.
abstract class QuicSendStream {
  int get streamId;
  
  /// Write data to the stream.
  void add(List<int> data);
  
  /// Write data and signal end-of-stream.
  Future<void> close();
  
  /// Abruptly terminate the stream.
  Future<void> reset(int errorCode);
  
  /// Completes when all data has been acknowledged.
  Future<void> get done;
}

/// A receive-only QUIC stream.
abstract class QuicReceiveStream {
  int get streamId;
  
  /// Incoming data as a stream of byte chunks.
  Stream<List<int>> get stream;
  
  /// Request the peer stop sending.
  Future<void> stopSending(int errorCode);
}
```

### 4.4 Configuration

```dart
/// QUIC connection configuration (maps to transport parameters).
class QuicConfiguration {
  /// Maximum idle timeout (0 = disabled).
  final Duration maxIdleTimeout;
  
  /// Initial flow control limits.
  final int initialMaxData;
  final int initialMaxStreamDataBidiLocal;
  final int initialMaxStreamDataBidiRemote;
  final int initialMaxStreamDataUni;
  
  /// Stream count limits.
  final int initialMaxStreamsBidi;
  final int initialMaxStreamsUni;
  
  /// Maximum UDP payload size.
  final int maxUdpPayloadSize;
  
  /// Enable datagrams (RFC 9221).
  final bool enableDatagrams;
  final int maxDatagramFrameSize;
  
  /// Enable connection migration.
  final bool enableMigration;
  
  /// Congestion control algorithm.
  final CongestionAlgorithm congestionAlgorithm;
  
  const QuicConfiguration({
    this.maxIdleTimeout = const Duration(seconds: 30),
    this.initialMaxData = 1048576,              // 1 MB
    this.initialMaxStreamDataBidiLocal = 262144, // 256 KB
    this.initialMaxStreamDataBidiRemote = 262144,
    this.initialMaxStreamDataUni = 262144,
    this.initialMaxStreamsBidi = 100,
    this.initialMaxStreamsUni = 100,
    this.maxUdpPayloadSize = 1200,
    this.enableDatagrams = false,
    this.maxDatagramFrameSize = 0,
    this.enableMigration = true,
    this.congestionAlgorithm = CongestionAlgorithm.newReno,
  });
}

enum CongestionAlgorithm {
  newReno,
  cubic,
}
```

---

## 5. Error Handling

### 5.1 Exception Hierarchy

```dart
/// Base exception for all QUIC errors.
abstract class QuicException implements Exception {
  final String message;
  final int? errorCode;
}

/// Connection-level error (connection closed).
class QuicConnectionException extends QuicException {
  final bool isApplicationError;  // vs transport error
  final String? reason;
}

/// Stream-level error (stream reset).
class QuicStreamException extends QuicException {
  final int streamId;
}

/// Handshake failed (TLS error).
class QuicHandshakeException extends QuicException {
  final String? tlsAlertDescription;
}

/// Connection timed out.
class QuicTimeoutException extends QuicException {}

/// Version negotiation required.
class QuicVersionNegotiationException extends QuicException {
  final List<int> supportedVersions;
}
```

### 5.2 Error Propagation

| Error Source | Dart Manifestation |
|-------------|-------------------|
| QUIC CONNECTION_CLOSE | `QuicConnectionException` on `connection.closed` |
| QUIC RESET_STREAM | `QuicStreamException` on `stream.stream` |
| TLS alert | `QuicHandshakeException` on `endpoint.connect()` |
| Idle timeout | `QuicTimeoutException` on `connection.closed` |
| Flow control violation | Connection closed with FLOW_CONTROL_ERROR |

---

## 6. dart:io Integration

### 6.1 SecurityContext

```dart
// Reuse Dart's SecurityContext for TLS certificate configuration
final ctx = SecurityContext()
  ..useCertificateChain('cert.pem')
  ..usePrivateKey('key.pem');

final endpoint = await QuicEndpoint.bind(
  InternetAddress.anyIPv4, 443,
  securityContext: ctx,
);
```

### 6.2 InternetAddress

Use Dart's `InternetAddress` for all address representations:
```dart
await endpoint.connect(
  InternetAddress('93.184.216.34'),  // or InternetAddress('::1')
  443,
);
```

### 6.3 Stream Integration

```dart
// Reading from a QUIC stream works like any Dart Stream
await for (final chunk in quicStream.stream) {
  process(chunk);
}

// Writing uses StreamSink semantics
quicStream.add(utf8.encode('Hello QUIC'));
await quicStream.close();

// Pipe between streams
someStream.pipe(quicStream);
```

---

## 7. HTTP/3 API

```dart
/// HTTP/3 client — simplified high-level API.
abstract class Http3Client {
  static Future<Http3Client> connect(
    Uri uri, {
    Http3Settings? settings,
    SecurityContext? securityContext,
  });
  
  /// Send an HTTP request and receive the response.
  Future<Http3Response> send(Http3Request request);
  
  /// Shorthand methods
  Future<Http3Response> get(Uri uri, {Map<String, String>? headers});
  Future<Http3Response> post(Uri uri, {Map<String, String>? headers, List<int>? body});
  
  /// Close the client and underlying connection.
  Future<void> close();
}
```

---

## 8. WebTransport API

See [WEBTRANSPORT_SPEC.md](./WEBTRANSPORT_SPEC.md) Section 9 for the full API definition.

---

## 9. libp2p API

See [LIBP2P_QUIC_SPEC.md](./LIBP2P_QUIC_SPEC.md) Section 11 for the full API definition.

---

## 10. Crypto Backend Abstraction

```dart
/// Abstract interface for cryptographic operations.
abstract class QuicCryptoBackend {
  /// AEAD encryption
  Future<List<int>> aesGcmEncrypt(List<int> key, List<int> nonce, List<int> aad, List<int> plaintext);
  Future<List<int>> aesGcmDecrypt(List<int> key, List<int> nonce, List<int> aad, List<int> ciphertext);
  
  /// ChaCha20-Poly1305
  Future<List<int>> chachaEncrypt(List<int> key, List<int> nonce, List<int> aad, List<int> plaintext);
  Future<List<int>> chachaDecrypt(List<int> key, List<int> nonce, List<int> aad, List<int> ciphertext);
  
  /// HKDF
  List<int> hkdfExtract(List<int> salt, List<int> ikm);
  List<int> hkdfExpand(List<int> prk, List<int> info, int length);
  
  /// Header protection
  List<int> aesEcbEncrypt(List<int> key, List<int> block);
  
  /// Hashing
  List<int> sha256(List<int> data);
  List<int> sha384(List<int> data);
  
  /// Random
  List<int> randomBytes(int length);
}

/// Default implementation using package:cryptography
class DefaultCryptoBackend implements QuicCryptoBackend { ... }
```

---

## 11. Connection Statistics

```dart
class QuicConnectionStats {
  final int bytesSent;
  final int bytesReceived;
  final int packetsSent;
  final int packetsReceived;
  final int packetsLost;
  final Duration smoothedRtt;
  final Duration minRtt;
  final int congestionWindow;
  final int bytesInFlight;
  final int streamsOpened;
  final int streamsClosed;
}
```

---

## 12. Acceptance Criteria

- [ ] All public APIs compile without errors.
- [ ] No `dart:ffi` imports in core library.
- [ ] All Future-returning methods are properly async.
- [ ] Stream subscriptions can be paused/resumed.
- [ ] SecurityContext integration works with PEM/DER certificates.
- [ ] Configuration defaults are sensible for common use cases.
- [ ] Exception hierarchy covers all error conditions.
- [ ] Crypto backend is swappable.
- [ ] APIs follow Dart naming conventions (lowerCamelCase methods, UpperCamelCase classes).
- [ ] All public members have dartdoc comments.

---

## 13. Security Considerations

- Never expose raw keys or secrets in public API return values.
- SecurityContext should be the only way to configure TLS credentials.
- Connection statistics must not leak timing information exploitable for traffic analysis.
- Graceful degradation: malformed input from the network never causes uncaught exceptions.

---

## 14. Dependencies

- `dart:io` (InternetAddress, RawDatagramSocket, SecurityContext)
- `dart:async` (Stream, Future, Completer, StreamController)
- `dart:typed_data` (Uint8List for efficient byte handling)
- `package:cryptography` (default crypto backend)
- No `dart:ffi`, no `dart:mirrors`

---

## 15. Testing Strategy

- API contracts: Verify all methods return correct types.
- Mock testing: Use mock I/O backends to test without network.
- Integration: Full client-server exchange.
- Documentation: All public APIs have examples in dartdoc.
- Lint: `package:dart_quic` passes `dart analyze` with no issues.

---

## References

- Dart IO Library: https://api.dart.dev/stable/dart-io/dart-io-library.html
- Effective Dart Design: https://dart.dev/effective-dart/design
- package:cryptography: https://pub.dev/packages/cryptography

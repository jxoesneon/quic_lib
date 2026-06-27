import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// A mock UDP socket that simulates [RawDatagramSocket] behaviour for tests.
///
/// Incoming datagrams are delivered via [incoming].  Outgoing datagrams
/// are captured in [sent].
class MockUdpSocket {
  final StreamController<Datagram> _incoming = StreamController<Datagram>.broadcast();
  final List<Datagram> sent = <Datagram>[];
  bool _closed = false;

  /// Stream of datagrams that would be received from the network.
  Stream<Datagram> get incoming => _incoming.stream;

  /// Adds a synthetic incoming datagram.  Useful from the test harness to
  /// inject packets.
  void inject(Datagram datagram) {
    if (_closed) return;
    _incoming.add(datagram);
  }

  /// Simulates sending a datagram.
  ///
  /// The datagram is appended to [sent] for later inspection.
  void send(List<int> data, InternetAddress address, int port) {
    if (_closed) {
      throw StateError('Socket is closed');
    }
    sent.add(Datagram(Uint8List.fromList(data), address, port));
  }

  /// Closes the socket and shuts down the incoming stream.
  void close() {
    _closed = true;
    _incoming.close();
  }

  /// Whether the socket has been closed.
  bool get isClosed => _closed;

  /// Returns a subscription-like handle for compatibility with code that
  /// expects `RawDatagramSocket.listen`.
  StreamSubscription<Datagram> listen(
    void Function(Datagram event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) {
    return _incoming.stream.listen(
      onData,
      onError: onError,
      onDone: onDone,
      cancelOnError: cancelOnError,
    );
  }
}

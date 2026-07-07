import 'dart:async';
import 'dart:io' show RawDatagramSocket, RawSocketEvent;
import 'dart:typed_data';

import 'platform_address.dart';
import 'udp_rate_limiter.dart';

/// Wrapper around [RawDatagramSocket] for QUIC.
class UdpSocket {
  /// Do not call directly; use [UdpSocket.bind] to create a socket.
  factory UdpSocket() => throw UnsupportedError('use UdpSocket.bind');

  final RawDatagramSocket _socket;
  final UdpRateLimiter _rateLimiter;
  late final StreamSubscription<RawSocketEvent> _subscription;
  final _incomingController = StreamController<
      ({Uint8List data, InternetAddress address, int port})>.broadcast();

  UdpSocket._(this._socket, this._rateLimiter) {
    _subscription = _socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final datagram = _socket.receive();
        if (datagram != null) {
          if (!_rateLimiter.isAllowed(datagram.address)) {
            // Drop datagram from flooding source.
            return;
          }
          _incomingController.add((
            data: datagram.data,
            address: datagram.address,
            port: datagram.port,
          ));
        }
      }
    });
  }

  /// Binds a UDP socket to the given [address] and [port].
  static Future<UdpSocket> bind(InternetAddress address, int port) async {
    final socket = await RawDatagramSocket.bind(address, port);
    return UdpSocket._(socket, UdpRateLimiter());
  }

  /// Stream of incoming UDP datagrams.
  Stream<({Uint8List data, InternetAddress address, int port})> get incoming =>
      _incomingController.stream;

  /// Sends [data] to the specified [address] and [port].
  void send(Uint8List data, InternetAddress address, int port) {
    _socket.send(data, address, port);
  }

  /// Closes the socket and stops receiving datagrams.
  void close() {
    _subscription.cancel();
    _socket.close();
    _incomingController.close();
  }

  /// The local address this socket is bound to.
  InternetAddress get localAddress => _socket.address;

  /// The local port this socket is bound to.
  int get localPort => _socket.port;
}

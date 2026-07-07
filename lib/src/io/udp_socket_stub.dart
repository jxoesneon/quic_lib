import 'dart:async';
import 'dart:typed_data';

import 'platform_address.dart';

/// Stub UDP socket implementation for web/WASM platforms.
class UdpSocket {
  /// Creates a stub UDP socket (throws on web/WASM platforms).
  UdpSocket();

  /// Binding is unsupported on web/WASM platforms.
  static Future<UdpSocket> bind(InternetAddress address, int port) async {
    throw UnsupportedError(
        'UDP sockets are not supported on web/WASM platforms.');
  }

  /// Incoming datagram stream; unsupported on web/WASM platforms.
  Stream<({Uint8List data, InternetAddress address, int port})> get incoming =>
      throw UnsupportedError('UDP not supported on web');

  /// Sends [data] to [address]:[port]; unsupported on web/WASM platforms.
  void send(Uint8List data, InternetAddress address, int port) =>
      throw UnsupportedError('UDP not supported on web');

  /// Closes the stub socket (no-op on web/WASM platforms).
  void close() {}

  /// Returns a placeholder local address on web/WASM platforms.
  InternetAddress get localAddress => InternetAddress('0.0.0.0');

  /// Returns a placeholder local port on web/WASM platforms.
  int get localPort => 0;
}

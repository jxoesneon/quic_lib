import 'dart:async';
import 'dart:typed_data';

import 'platform_address.dart';

class UdpSocket {
  static Future<UdpSocket> bind(InternetAddress address, int port) async {
    throw UnsupportedError(
        'UDP sockets are not supported on web/WASM platforms.');
  }

  Stream<({Uint8List data, InternetAddress address, int port})> get incoming =>
      throw UnsupportedError('UDP not supported on web');

  void send(Uint8List data, InternetAddress address, int port) =>
      throw UnsupportedError('UDP not supported on web');

  void close() {}

  InternetAddress get localAddress => InternetAddress('0.0.0.0');
  int get localPort => 0;
}

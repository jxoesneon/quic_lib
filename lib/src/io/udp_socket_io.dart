import 'dart:async';
import 'dart:io' show RawDatagramSocket, RawSocketEvent;
import 'dart:typed_data';

import 'platform_address.dart';

/// Wrapper around [RawDatagramSocket] for QUIC.
class UdpSocket {
  // SECURITY: Per-IP datagram rate limit to prevent UDP flood DoS.
  static const int _maxDatagramsPerIpPerSecond = 1000;
  static const int _rateLimitWindowMs = 1000;
  // SECURITY: Cap tracked IPs to prevent memory exhaustion from spoofed sources.
  static const int _maxTrackedIps = 10000;

  final RawDatagramSocket _socket;
  late final StreamSubscription<RawSocketEvent> _subscription;
  final _incomingController = StreamController<
      ({Uint8List data, InternetAddress address, int port})>.broadcast();

  /// Per-source IP rate tracking: ip_string → List<timestamp_ms>.
  final Map<String, List<int>> _ipTimestamps = {};

  UdpSocket._(this._socket) {
    _subscription = _socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final datagram = _socket.receive();
        if (datagram != null) {
          if (_isRateLimited(datagram.address)) {
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

  bool _isRateLimited(InternetAddress address) {
    final now = DateTime.now().millisecondsSinceEpoch;
    final ipKey = address.address;

    // SECURITY: Evict oldest tracked IP if at capacity.
    if (_ipTimestamps.length >= _maxTrackedIps &&
        !_ipTimestamps.containsKey(ipKey)) {
      _evictOldestIp();
    }

    final timestamps = _ipTimestamps.putIfAbsent(ipKey, () => []);
    // Prune old timestamps outside the window.
    final cutoff = now - _rateLimitWindowMs;
    timestamps.removeWhere((t) => t < cutoff);
    if (timestamps.length >= _maxDatagramsPerIpPerSecond) {
      return true;
    }
    timestamps.add(now);
    return false;
  }

  void _evictOldestIp() {
    String? oldestKey;
    int? oldestTime;
    for (final entry in _ipTimestamps.entries) {
      final newest = entry.value.isEmpty ? 0 : entry.value.last;
      if (oldestTime == null || newest < oldestTime) {
        oldestTime = newest;
        oldestKey = entry.key;
      }
    }
    if (oldestKey != null) {
      _ipTimestamps.remove(oldestKey);
    }
  }

  /// Binds a UDP socket to the given [address] and [port].
  static Future<UdpSocket> bind(InternetAddress address, int port) async {
    final socket = await RawDatagramSocket.bind(address, port);
    return UdpSocket._(socket);
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

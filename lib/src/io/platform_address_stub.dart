/// Stub InternetAddress for web/WASM platforms.
class InternetAddress {
  final String address;
  InternetAddress(this.address);

  /// Returns the raw bytes of the address.
  List<int> get rawAddress {
    if (address.contains(':')) {
      // IPv6 stub: return 16 zero bytes.
      return List<int>.filled(16, 0);
    }
    // IPv4: parse dotted-decimal string.
    return address.split('.').map(int.parse).toList();
  }

  static InternetAddress get anyIPv4 => InternetAddress('0.0.0.0');
  static InternetAddress get loopbackIPv4 => InternetAddress('127.0.0.1');
  static InternetAddress get anyIPv6 => InternetAddress('::');
  static InternetAddress get loopbackIPv6 => InternetAddress('::1');
}

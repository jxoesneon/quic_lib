/// Stub InternetAddress for web/WASM platforms.
class InternetAddress {
  final String address;
  InternetAddress(this.address);
  static InternetAddress get anyIPv4 => InternetAddress('0.0.0.0');
  static InternetAddress get loopbackIPv4 => InternetAddress('127.0.0.1');
  static InternetAddress get anyIPv6 => InternetAddress('::');
  static InternetAddress get loopbackIPv6 => InternetAddress('::1');
}

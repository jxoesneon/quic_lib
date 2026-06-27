/// Lightweight logging abstraction for dart_quic.
///
/// Production code should set [QuicLogger.sink] to a no-op or structured
/// logger. The default sink prints to stdout for development convenience.
///
/// SECURITY: Never log secrets, keys, or raw packet payloads.
class QuicLogger {
  static void Function(String message) _sink = _defaultSink;

  static void Function(String message) get sink => _sink;

  /// Replace the default sink with a custom handler.
  /// Pass a no-op to disable logging entirely in production.
  static void setSink(void Function(String message)? handler) {
    _sink = handler ?? _defaultSink;
  }

  /// Log a message.
  static void log(String message) => _sink(message);

  static void _defaultSink(String message) {
    // ignore: avoid_print
    print(message);
  }
}

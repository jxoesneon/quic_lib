import 'dart:typed_data';

/// Simple in-memory store for TLS session tickets.
///
/// Enables QUIC 0-RTT session resumption by storing encrypted ticket blobs
/// keyed by an identifier (e.g. SNI or a cached session ID).
class SessionTicketStore {
  final Map<String, Uint8List> _tickets = {};

  /// Store a [ticket] under [identifier].
  void store(String identifier, List<int> ticket) {
    _tickets[identifier] = Uint8List.fromList(ticket);
  }

  /// Retrieve a previously stored ticket, or `null` if not found.
  Uint8List? retrieve(String identifier) {
    final bytes = _tickets[identifier];
    return bytes == null ? null : Uint8List.fromList(bytes);
  }

  /// Returns `true` if a ticket exists for [identifier].
  bool contains(String identifier) => _tickets.containsKey(identifier);

  /// Remove the ticket for [identifier].
  void remove(String identifier) => _tickets.remove(identifier);

  /// Clear all stored tickets.
  void clear() => _tickets.clear();
}

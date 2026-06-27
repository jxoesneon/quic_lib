import 'crypto_backend.dart';

class _TicketEntry {
  final SecretKey psk;
  final DateTime expiry;

  _TicketEntry(this.psk, this.expiry);
}

/// In-memory store for PSKs (session resumption tickets).
///
/// SECURITY: Enforces a maximum of 100 tickets. When the store overflows,
/// the oldest ticket (by insertion order) is evicted.
class SessionTicketStore {
  static const int maxTickets = 100;

  final _tickets = <String, _TicketEntry>{};

  /// Store a PSK with an associated ticket ID and expiry time.
  ///
  /// If [ticketId] already exists, it is refreshed (moved to newest
  /// insertion order). When the store exceeds [maxTickets], the oldest
  /// ticket is evicted.
  void store(String ticketId, SecretKey psk, DateTime expiry) {
    // Remove first so re-insertion moves it to the end (newest).
    _tickets.remove(ticketId);

    if (_tickets.length >= maxTickets) {
      final oldestId = _tickets.keys.first;
      _tickets.remove(oldestId);
    }

    _tickets[ticketId] = _TicketEntry(psk, expiry);
  }

  /// Retrieve a PSK by ticket ID if it has not expired.
  ///
  /// Returns `null` if the ticket does not exist or has expired.
  /// Expired tickets are removed on access.
  SecretKey? retrieve(String ticketId) {
    final entry = _tickets[ticketId];
    if (entry == null) return null;

    if (DateTime.now().isAfter(entry.expiry)) {
      _tickets.remove(ticketId);
      return null;
    }

    return entry.psk;
  }

  /// Remove a ticket from the store.
  void remove(String ticketId) {
    _tickets.remove(ticketId);
  }

  /// Returns a list of all non-expired ticket IDs.
  List<String> get validTicketIds {
    final now = DateTime.now();
    return _tickets.entries
        .where((e) => !now.isAfter(e.value.expiry))
        .map((e) => e.key)
        .toList();
  }
}

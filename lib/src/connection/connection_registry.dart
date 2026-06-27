/// A registry that maps destination connection IDs to connection objects.
///
/// Uses hex-encoded keys for fast string-based lookup in a [Map].
class ConnectionRegistry {
  // SECURITY: Limits per RFC 9000.
  static const int maxConnections = 65536;
  static const int minCidLength = 1;
  static const int maxCidLength = 20;

  final Map<String, Object> _registry = {};

  /// Registers a connection object under the given [connectionId].
  ///
  /// Overwrites any existing mapping for the same ID.
  ///
  /// Throws [ArgumentError] if the CID length is invalid or the registry is full.
  void register(List<int> connectionId, Object connection) {
    if (connectionId.length < minCidLength || connectionId.length > maxCidLength) {
      throw ArgumentError(
        'CID length must be $minCidLength..$maxCidLength, got ${connectionId.length}',
      );
    }
    final key = _encodeKey(connectionId);
    if (!_registry.containsKey(key) && _registry.length >= maxConnections) {
      throw StateError('ConnectionRegistry: max connections ($maxConnections) reached');
    }
    _registry[key] = connection;
  }

  /// Looks up the connection object associated with [connectionId].
  ///
  /// Returns `null` if no mapping exists.
  Object? lookup(List<int> connectionId) {
    return _registry[_encodeKey(connectionId)];
  }

  /// Removes the mapping for [connectionId] if it exists.
  void unregister(List<int> connectionId) {
    _registry.remove(_encodeKey(connectionId));
  }

  /// Returns the number of registered connection ID mappings.
  int get length => _registry.length;

  // --------------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------------

  String _encodeKey(List<int> bytes) {
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

import 'dart:math';
import 'dart:typed_data';

/// Record representing an active Connection ID.
typedef ConnectionIdRecord = ({
  List<int> connectionId,
  int sequenceNumber,
  List<int> statelessResetToken,
});

/// Manages the lifecycle of Connection IDs for a single QUIC connection.
///
/// Implements the server-side (or endpoint-side) CID issuance and retirement
/// logic described in RFC 9000 Section 19.15 and 19.16.
class ConnectionIdManager {
  static const int maxActiveIds = 8;
  static const int minConnectionIdLength = 8;
  static const int maxConnectionIdLength = 20;
  static const int statelessResetTokenLength = 16;
  // SECURITY: Cap retired CID history to prevent unbounded growth.
  static const int maxRetiredIds = 32;

  final _random = Random.secure();

  int _nextSequenceNumber = 0;

  /// Active CIDs indexed by sequence number.
  final Map<int, _ConnectionIdEntry> _active = {};

  /// Retired CIDs kept for duplicate-detection.
  final Map<int, _ConnectionIdEntry> _retired = {};

  /// Fast lookup from CID bytes -> sequence number.
  final Map<String, int> _cidToSequence = {};

  /// Issues a new connection ID with an associated stateless reset token.
  ///
  /// If [retirePriorTo] is non-zero, all active CIDs whose sequence number
  /// is strictly less than [retirePriorTo] are moved to the retired set.
  ///
  /// Throws [StateError] if adding the new CID would exceed [maxActiveIds].
  ConnectionIdRecord issueNewId({int retirePriorTo = 0}) {
    // Retire everything older than retirePriorTo.
    if (retirePriorTo > 0) {
      final toRetire = <int>[];
      for (final seq in _active.keys) {
        if (seq < retirePriorTo) {
          toRetire.add(seq);
        }
      }
      for (final seq in toRetire) {
        retireId(seq);
      }
    }

    if (_active.length >= maxActiveIds) {
      throw StateError(
        'Cannot issue new connection ID: maxActiveIds ($maxActiveIds) reached.',
      );
    }

    final cid = _generateUniqueConnectionId();
    final token = _generateSecureBytes(statelessResetTokenLength);
    final seq = _nextSequenceNumber++;

    final entry = _ConnectionIdEntry(
      connectionId: cid,
      sequenceNumber: seq,
      statelessResetToken: token,
    );

    _active[seq] = entry;
    _cidToSequence[_encodeKey(cid)] = seq;

    return (
      connectionId: List<int>.unmodifiable(cid),
      sequenceNumber: seq,
      statelessResetToken: List<int>.unmodifiable(token),
    );
  }

  /// Retires a connection ID by sequence number.
  ///
  /// No-op if the sequence number is not currently active.
  void retireId(int sequenceNumber) {
    final entry = _active.remove(sequenceNumber);
    if (entry == null) return;

    _cidToSequence.remove(_encodeKey(entry.connectionId));
    // SECURITY: Evict oldest retired CID if at capacity.
    while (_retired.length >= maxRetiredIds) {
      final oldest = _retired.keys.reduce((a, b) => a < b ? a : b);
      _retired.remove(oldest);
    }
    _retired[sequenceNumber] = entry;
  }

  /// Register an externally received connection ID.
  ///
  /// Used when a peer sends us a NEW_CONNECTION_ID frame.
  void registerId({
    required List<int> connectionId,
    required int sequenceNumber,
    required List<int> statelessResetToken,
  }) {
    if (_active.length >= maxActiveIds) {
      throw StateError(
        'Cannot register connection ID: maxActiveIds ($maxActiveIds) reached.',
      );
    }
    final entry = _ConnectionIdEntry(
      connectionId: List<int>.from(connectionId),
      sequenceNumber: sequenceNumber,
      statelessResetToken: List<int>.from(statelessResetToken),
    );
    _active[sequenceNumber] = entry;
    _cidToSequence[_encodeKey(connectionId)] = sequenceNumber;
  }

  /// Returns `true` if [connectionId] is currently in the active set.
  bool isValidId(List<int> connectionId) {
    final seq = lookupSequenceNumber(connectionId);
    if (seq == null) return false;
    return _active.containsKey(seq);
  }

  /// Looks up the sequence number for an active connection ID.
  ///
  /// Returns `null` if the CID is unknown or retired.
  int? lookupSequenceNumber(List<int> connectionId) {
    return _cidToSequence[_encodeKey(connectionId)];
  }

  /// Returns a snapshot of all currently active connection IDs.
  List<ConnectionIdRecord> get activeIds {
    return _active.values.map((e) => e.toRecord()).toList();
  }

  // --------------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------------

  List<int> _generateUniqueConnectionId() {
    const maxAttempts = 1000;
    for (var attempt = 0; attempt < maxAttempts; attempt++) {
      final length = minConnectionIdLength +
          _random.nextInt(maxConnectionIdLength - minConnectionIdLength + 1);
      final cid = _generateSecureBytes(length);
      final key = _encodeKey(cid);
      if (!_cidToSequence.containsKey(key) &&
          !_retired.values.any((e) => _encodeKey(e.connectionId) == key)) {
        return cid;
      }
    }
    throw StateError(
      'Unable to generate a unique connection ID after $maxAttempts attempts.',
    );
  }

  List<int> _generateSecureBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  String _encodeKey(List<int> bytes) {
    // Using a fast hex encoder. Each byte becomes two hex characters.
    final buffer = StringBuffer();
    for (final b in bytes) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }
}

class _ConnectionIdEntry {
  final List<int> connectionId;
  final int sequenceNumber;
  final List<int> statelessResetToken;

  _ConnectionIdEntry({
    required this.connectionId,
    required this.sequenceNumber,
    required this.statelessResetToken,
  });

  ConnectionIdRecord toRecord() => (
        connectionId: List<int>.unmodifiable(connectionId),
        sequenceNumber: sequenceNumber,
        statelessResetToken: List<int>.unmodifiable(statelessResetToken),
      );
}

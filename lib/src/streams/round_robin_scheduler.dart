import 'stream_scheduler.dart';

/// A round-robin implementation of [StreamScheduler].
///
/// Cycles through active stream IDs in ascending order, wrapping back to
/// the smallest ID after reaching the largest.
class RoundRobinScheduler implements StreamScheduler {
  int? _lastStreamId;

  @override
  int selectNextStream(List<int> activeStreamIds) {
    if (activeStreamIds.isEmpty) {
      throw ArgumentError('activeStreamIds must not be empty');
    }
    final sorted = activeStreamIds.toList()..sort();
    if (_lastStreamId == null) {
      _lastStreamId = sorted.first;
      return _lastStreamId!;
    }
    for (final id in sorted) {
      if (id > _lastStreamId!) {
        _lastStreamId = id;
        return id;
      }
    }
    // Wrap around to the beginning.
    _lastStreamId = sorted.first;
    return _lastStreamId!;
  }
}

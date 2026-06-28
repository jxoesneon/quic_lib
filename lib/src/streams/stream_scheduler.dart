/// Abstract interface for selecting the next QUIC stream to process.
///
/// Different applications have different scheduling needs: a web server
/// may prioritize certain streams; a libp2p node may want fair bandwidth
/// sharing; a media client may prioritize video over metadata. Implementing
/// this interface allows custom schedulers to be injected into
/// StreamManager.
abstract class StreamScheduler {
  /// Select the next stream ID to process from [activeStreamIds].
  ///
  /// [activeStreamIds] is guaranteed to be non-empty.
  int selectNextStream(List<int> activeStreamIds);
}

/// Abstract congestion controller interface for QUIC connections.
///
/// Implementations must track bytes in flight and compute a congestion window
/// in bytes. All [size] and [bytes] parameters are in bytes.
abstract class CongestionController {
  /// Current congestion window in bytes.
  int get congestionWindow;

  /// Bytes currently in flight.
  int get bytesInFlight;

  /// Register a sent packet.
  ///
  /// [packetNumber] is the packet number and [size] is the payload size in
  /// bytes.
  void onPacketSent(int packetNumber, int size);

  /// Process an ACK.
  ///
  /// [largestAcked] is the largest packet number acknowledged.
  /// [newlyAckedBytes] is the total newly acknowledged bytes.
  /// [now] is the current time.
  void onAckReceived(int largestAcked, int newlyAckedBytes, DateTime now);

  /// React to a detected packet loss.
  ///
  /// [packetNumber] is the lost packet number.
  /// [lostBytes] is the size of the lost packet in bytes.
  /// [now] is the current time.
  void onPacketLost(int packetNumber, int lostBytes, DateTime now);

  /// Record an RTT sample.
  void onRttSample(Duration rtt);

  /// React to ECN Congestion Experienced (CE) marks.
  void onECNCEMarked(int count);

  /// Reset to initial state.
  void reset();

  /// Whether sending [bytes] would exceed the congestion window.
  bool canSend(int bytes);

  /// Whether the application is currently limited (not sending enough
  /// to fill the congestion window).
  bool get appLimited;

  /// Set the application-limited state.
  void setAppLimited(bool limited);

  /// React to persistent congestion being declared (RFC 9002 §7.6).
  void onPersistentCongestion();
}

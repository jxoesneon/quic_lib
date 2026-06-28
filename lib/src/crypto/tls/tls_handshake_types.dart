/// Identifiers for TLS 1.3 handshake message types (RFC 8446 Section 4).
///
/// Each value corresponds to the `HandshakeType` byte that appears in the
/// header of every TLS handshake message. These types are used by the
/// [HandshakeStateMachine] to route incoming messages and by frame builders
/// to construct CRYPTO frames.
///
/// See also:
/// - [HandshakeStateMachine] — uses these types to advance handshake state.
/// - [TlsContentType] — the record-layer content type that wraps handshake data.
/// - RFC 8446 Section 4 — handshake protocol message definitions.
enum TlsHandshakeType {
  clientHello(0x01),
  serverHello(0x02),
  newSessionTicket(0x04),
  endOfEarlyData(0x05),
  encryptedExtensions(0x08),
  certificate(0x0b),
  certificateRequest(0x0d),
  certificateVerify(0x0f),
  finished(0x14),
  keyUpdate(0x18),
  messageHash(0xfe);

  final int value;
  const TlsHandshakeType(this.value);
}

/// TLS record-layer content types (RFC 8446 Section 5.1).
///
/// The content type determines how the payload of a TLS record is interpreted.
/// In QUIC, most records carry [applicationData] because handshake messages
/// are encapsulated inside CRYPTO frames; however, [alert] records are still
/// used for fatal errors.
///
/// See also:
/// - [TlsHandshakeType] — the handshake message types carried within records.
/// - RFC 8446 Section 5.1 — record layer overview.
enum TlsContentType {
  changeCipherSpec(0x14),
  alert(0x15),
  handshake(0x16),
  applicationData(0x17);

  final int value;
  const TlsContentType(this.value);
}

/// TLS extension type identifiers (RFC 8446 Section 4.2).
///
/// Extensions allow TLS handshake messages to carry additional parameters
/// negotiated between client and server. [quicTransportParameters] (0x0039)
/// is defined in RFC 9001 and is essential for QUIC-capable connections.
///
/// See also:
/// - [TlsHandshakeType] — the messages that may carry these extensions.
/// - RFC 8446 Section 4.2 — standard TLS extensions.
/// - RFC 9001 Section 8.2 — QUIC transport parameters extension.
enum TlsExtensionType {
  serverName(0x0000),
  maxFragmentLength(0x0001),
  statusRequest(0x0005),
  supportedGroups(0x000a),
  signatureAlgorithms(0x000d),
  useSrtp(0x000e),
  heartbeat(0x000f),
  applicationLayerProtocolNegotiation(0x0010),
  signedCertificateTimestamp(0x0012),
  clientCertificateType(0x0013),
  serverCertificateType(0x0014),
  padding(0x0015),
  preSharedKey(0x0029),
  earlyData(0x002a),
  supportedVersions(0x002b),
  cookie(0x002c),
  pskModes(0x002d),
  certificateAuthorities(0x002f),
  oidFilters(0x0030),
  postHandshakeAuth(0x0031),
  signatureAlgorithmsCert(0x0032),
  keyShare(0x0033),
  quicTransportParameters(0x0039); // RFC 9001

  final int value;
  const TlsExtensionType(this.value);
}

/// QUIC transport parameter identifiers (RFC 9000 and extensions).
///
/// Transport parameters are carried in the `quic_transport_parameters`
/// TLS extension (RFC 9001) and negotiated during the handshake.
enum QuicTransportParameterId {
  originalDestinationConnectionId(0x00),
  maxIdleTimeout(0x01),
  statelessResetToken(0x02),
  maxUdpPayloadSize(0x03),
  initialMaxData(0x04),
  initialMaxStreamDataBidiLocal(0x05),
  initialMaxStreamDataBidiRemote(0x06),
  initialMaxStreamDataUni(0x07),
  initialMaxStreamsBidi(0x08),
  initialMaxStreamsUni(0x09),
  ackDelayExponent(0x0a),
  maxAckDelay(0x0b),
  disableActiveMigration(0x0c), // RFC 9000 Section 9
  preferredAddress(0x0d), // RFC 9000 Section 9.6
  activeConnectionIdLimit(0x0e),
  initialSourceConnectionId(0x0f),
  retrySourceConnectionId(0x10),
  versionInformation(0x11), // RFC 9368
  maxDatagramFrameSize(0x20), // RFC 9221
  greaseQuicBit(0x2ab2), // RFC 9287
  earlyData(0x42); // RFC 9001

  final int value;
  const QuicTransportParameterId(this.value);
}

/// Protocol-wide constants for TLS 1.3 (RFC 8446).
///
/// These values are used when building or parsing TLS handshake messages,
/// ensuring that wire-format sizes and version fields match the specification.
///
/// See also:
/// - [TlsHandshakeType] — message types that rely on these constants.
/// - RFC 8446 Section 4.1 — protocol version and random structure.
class TlsConstants {
  /// TLS 1.3 version (0x0304).
  static const int tls13Version = 0x0304;

  /// TLS 1.2 version (0x0303) for compatibility.
  static const int tls12Version = 0x0303;

  /// Random size in bytes.
  static const int randomSize = 32;

  /// Session ID size in bytes (legacy, always 0 for TLS 1.3).
  static const int sessionIdSize = 0;

  /// Minimum TLS record size.
  static const int minRecordSize = 5;
}

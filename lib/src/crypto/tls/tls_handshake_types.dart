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
  /// ClientHello handshake message.
  clientHello(0x01),

  /// ServerHello handshake message.
  serverHello(0x02),

  /// NewSessionTicket handshake message.
  newSessionTicket(0x04),

  /// EndOfEarlyData handshake message.
  endOfEarlyData(0x05),

  /// EncryptedExtensions handshake message.
  encryptedExtensions(0x08),

  /// Certificate handshake message.
  certificate(0x0b),

  /// CertificateRequest handshake message.
  certificateRequest(0x0d),

  /// CertificateVerify handshake message.
  certificateVerify(0x0f),

  /// Finished handshake message.
  finished(0x14),

  /// KeyUpdate handshake message.
  keyUpdate(0x18),

  /// Synthetic message hash used for transcript re-derivation.
  messageHash(0xfe);

  /// Wire value of the handshake type.
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
  /// ChangeCipherSpec content type (not used in TLS 1.3).
  changeCipherSpec(0x14),

  /// Alert content type.
  alert(0x15),

  /// Handshake content type.
  handshake(0x16),

  /// ApplicationData content type.
  applicationData(0x17);

  /// Wire value of the content type.
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
  /// Server Name Indication extension.
  serverName(0x0000),

  /// Maximum fragment length extension.
  maxFragmentLength(0x0001),

  /// Certificate status request extension.
  statusRequest(0x0005),

  /// Supported groups extension.
  supportedGroups(0x000a),

  /// Signature algorithms extension.
  signatureAlgorithms(0x000d),

  /// SRTP protection profiles extension.
  useSrtp(0x000e),

  /// Heartbeat extension.
  heartbeat(0x000f),

  /// Application-Layer Protocol Negotiation extension.
  applicationLayerProtocolNegotiation(0x0010),

  /// Signed certificate timestamp extension.
  signedCertificateTimestamp(0x0012),

  /// Client certificate type extension.
  clientCertificateType(0x0013),

  /// Server certificate type extension.
  serverCertificateType(0x0014),

  /// Padding extension.
  padding(0x0015),

  /// Pre-shared key extension.
  preSharedKey(0x0029),

  /// Early data indication extension.
  earlyData(0x002a),

  /// Supported versions extension.
  supportedVersions(0x002b),

  /// Cookie extension.
  cookie(0x002c),

  /// PSK key exchange modes extension.
  pskModes(0x002d),

  /// Certificate authorities extension.
  certificateAuthorities(0x002f),

  /// OID filters extension.
  oidFilters(0x0030),

  /// Post-handshake client authentication extension.
  postHandshakeAuth(0x0031),

  /// Signature algorithms for certificates extension.
  signatureAlgorithmsCert(0x0032),

  /// Key share extension.
  keyShare(0x0033),

  /// QUIC transport parameters extension (RFC 9001).
  quicTransportParameters(0x0039); // RFC 9001

  /// Wire value of the extension type.
  final int value;
  const TlsExtensionType(this.value);
}

/// QUIC transport parameter identifiers (RFC 9000 and extensions).
///
/// Transport parameters are carried in the `quic_transport_parameters`
/// TLS extension (RFC 9001) and negotiated during the handshake.
enum QuicTransportParameterId {
  /// Original destination connection ID.
  originalDestinationConnectionId(0x00),

  /// Maximum idle timeout in milliseconds.
  maxIdleTimeout(0x01),

  /// Stateless reset token.
  statelessResetToken(0x02),

  /// Maximum UDP payload size.
  maxUdpPayloadSize(0x03),

  /// Initial flow-control limit for connection-level data.
  initialMaxData(0x04),

  /// Initial stream data limit for locally-initiated bidirectional streams.
  initialMaxStreamDataBidiLocal(0x05),

  /// Initial stream data limit for peer-initiated bidirectional streams.
  initialMaxStreamDataBidiRemote(0x06),

  /// Initial stream data limit for unidirectional streams.
  initialMaxStreamDataUni(0x07),

  /// Initial maximum number of bidirectional streams.
  initialMaxStreamsBidi(0x08),

  /// Initial maximum number of unidirectional streams.
  initialMaxStreamsUni(0x09),

  /// ACK delay exponent.
  ackDelayExponent(0x0a),

  /// Maximum ACK delay.
  maxAckDelay(0x0b),

  /// Disable active migration (RFC 9000 Section 9).
  disableActiveMigration(0x0c), // RFC 9000 Section 9

  /// Preferred address for connection migration (RFC 9000 Section 9.6).
  preferredAddress(0x0d), // RFC 9000 Section 9.6

  /// Active connection ID limit.
  activeConnectionIdLimit(0x0e),

  /// Initial source connection ID.
  initialSourceConnectionId(0x0f),

  /// Retry source connection ID.
  retrySourceConnectionId(0x10),

  /// Version information for compatible version negotiation (RFC 9368).
  versionInformation(0x11), // RFC 9368

  /// Maximum DATAGRAM frame size (RFC 9221).
  maxDatagramFrameSize(0x20), // RFC 9221

  /// Greased QUIC bit support (RFC 9287).
  greaseQuicBit(0x2ab2), // RFC 9287

  /// Early data acceptance (RFC 9001).
  earlyData(0x42); // RFC 9001

  /// Wire value of the transport parameter identifier.
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
  /// Creates a TLS constants helper (all members are static).
  TlsConstants();

  /// TLS 1.3 version (0x0304).
  static const int tls13Version = 0x0304;

  /// TLS 1.2 version (0x0303) used for compatibility.
  static const int tls12Version = 0x0303;

  /// Random size in bytes.
  static const int randomSize = 32;

  /// Session ID size in bytes (legacy, always 0 for TLS 1.3).
  static const int sessionIdSize = 0;

  /// Minimum TLS record size in bytes.
  static const int minRecordSize = 5;
}

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

enum TlsContentType {
  changeCipherSpec(0x14),
  alert(0x15),
  handshake(0x16),
  applicationData(0x17);
  
  final int value;
  const TlsContentType(this.value);
}

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

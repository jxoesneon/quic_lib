import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/tls_handshake_types.dart';

void main() {
  group('TlsHandshakeType', () {
    test('enum values match RFC 8446 constants', () {
      expect(TlsHandshakeType.clientHello.value, 0x01);
      expect(TlsHandshakeType.serverHello.value, 0x02);
      expect(TlsHandshakeType.newSessionTicket.value, 0x04);
      expect(TlsHandshakeType.endOfEarlyData.value, 0x05);
      expect(TlsHandshakeType.encryptedExtensions.value, 0x08);
      expect(TlsHandshakeType.certificate.value, 0x0b);
      expect(TlsHandshakeType.certificateRequest.value, 0x0d);
      expect(TlsHandshakeType.certificateVerify.value, 0x0f);
      expect(TlsHandshakeType.finished.value, 0x14);
      expect(TlsHandshakeType.keyUpdate.value, 0x18);
      expect(TlsHandshakeType.messageHash.value, 0xfe);
    });
  });

  group('TlsContentType', () {
    test('enum values match RFC constants', () {
      expect(TlsContentType.changeCipherSpec.value, 0x14);
      expect(TlsContentType.alert.value, 0x15);
      expect(TlsContentType.handshake.value, 0x16);
      expect(TlsContentType.applicationData.value, 0x17);
    });
  });

  group('TlsExtensionType', () {
    test('extension type values are correct', () {
      expect(TlsExtensionType.serverName.value, 0x0000);
      expect(TlsExtensionType.maxFragmentLength.value, 0x0001);
      expect(TlsExtensionType.statusRequest.value, 0x0005);
      expect(TlsExtensionType.supportedGroups.value, 0x000a);
      expect(TlsExtensionType.signatureAlgorithms.value, 0x000d);
      expect(TlsExtensionType.useSrtp.value, 0x000e);
      expect(TlsExtensionType.heartbeat.value, 0x000f);
      expect(
          TlsExtensionType.applicationLayerProtocolNegotiation.value, 0x0010);
      expect(TlsExtensionType.signedCertificateTimestamp.value, 0x0012);
      expect(TlsExtensionType.clientCertificateType.value, 0x0013);
      expect(TlsExtensionType.serverCertificateType.value, 0x0014);
      expect(TlsExtensionType.padding.value, 0x0015);
      expect(TlsExtensionType.preSharedKey.value, 0x0029);
      expect(TlsExtensionType.earlyData.value, 0x002a);
      expect(TlsExtensionType.supportedVersions.value, 0x002b);
      expect(TlsExtensionType.cookie.value, 0x002c);
      expect(TlsExtensionType.pskModes.value, 0x002d);
      expect(TlsExtensionType.certificateAuthorities.value, 0x002f);
      expect(TlsExtensionType.oidFilters.value, 0x0030);
      expect(TlsExtensionType.postHandshakeAuth.value, 0x0031);
      expect(TlsExtensionType.signatureAlgorithmsCert.value, 0x0032);
      expect(TlsExtensionType.keyShare.value, 0x0033);
      expect(TlsExtensionType.quicTransportParameters.value, 0x0039);
    });
  });

  group('QuicTransportParameterId', () {
    test('RFC 9000 Section 18.2 parameters have correct values', () {
      expect(QuicTransportParameterId.originalDestinationConnectionId.value, 0x00);
      expect(QuicTransportParameterId.maxIdleTimeout.value, 0x01);
      expect(QuicTransportParameterId.statelessResetToken.value, 0x02);
      expect(QuicTransportParameterId.maxUdpPayloadSize.value, 0x03);
      expect(QuicTransportParameterId.initialMaxData.value, 0x04);
      expect(QuicTransportParameterId.initialMaxStreamDataBidiLocal.value, 0x05);
      expect(QuicTransportParameterId.initialMaxStreamDataBidiRemote.value, 0x06);
      expect(QuicTransportParameterId.initialMaxStreamDataUni.value, 0x07);
      expect(QuicTransportParameterId.initialMaxStreamsBidi.value, 0x08);
      expect(QuicTransportParameterId.initialMaxStreamsUni.value, 0x09);
      expect(QuicTransportParameterId.ackDelayExponent.value, 0x0a);
      expect(QuicTransportParameterId.maxAckDelay.value, 0x0b);
      expect(QuicTransportParameterId.disableActiveMigration.value, 0x0c);
      expect(QuicTransportParameterId.preferredAddress.value, 0x0d);
      expect(QuicTransportParameterId.activeConnectionIdLimit.value, 0x0e);
      expect(QuicTransportParameterId.initialSourceConnectionId.value, 0x0f);
      expect(QuicTransportParameterId.retrySourceConnectionId.value, 0x10);
    });

    test('maxDatagramFrameSize value is 0x20', () {
      expect(QuicTransportParameterId.maxDatagramFrameSize.value, 0x20);
    });

    test('versionInformation value is 0x11', () {
      expect(QuicTransportParameterId.versionInformation.value, 0x11);
    });
  });

  group('TlsConstants', () {
    test('TLS version constants are correct', () {
      expect(TlsConstants.tls13Version, 0x0304);
      expect(TlsConstants.tls12Version, 0x0303);
    });

    test('size constants are correct', () {
      expect(TlsConstants.randomSize, 32);
      expect(TlsConstants.sessionIdSize, 0);
      expect(TlsConstants.minRecordSize, 5);
    });
  });
}

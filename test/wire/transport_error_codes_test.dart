import 'package:test/test.dart';
import 'package:quic_lib/src/wire/transport_error_codes.dart';

void main() {
  group('QuicTransportErrorCode', () {
    test('all 17 RFC 9000 error codes have correct values', () {
      expect(QuicTransportErrorCode.noError.value, 0x00);
      expect(QuicTransportErrorCode.internalError.value, 0x01);
      expect(QuicTransportErrorCode.connectionRefused.value, 0x02);
      expect(QuicTransportErrorCode.flowControlError.value, 0x03);
      expect(QuicTransportErrorCode.streamLimitError.value, 0x04);
      expect(QuicTransportErrorCode.streamStateError.value, 0x05);
      expect(QuicTransportErrorCode.finalSizeError.value, 0x06);
      expect(QuicTransportErrorCode.frameEncodingError.value, 0x07);
      expect(QuicTransportErrorCode.transportParameterError.value, 0x08);
      expect(QuicTransportErrorCode.connectionIdLimitError.value, 0x09);
      expect(QuicTransportErrorCode.protocolViolation.value, 0x0a);
      expect(QuicTransportErrorCode.invalidToken.value, 0x0b);
      expect(QuicTransportErrorCode.applicationError.value, 0x0c);
      expect(QuicTransportErrorCode.cryptoBufferExceeded.value, 0x0d);
      expect(QuicTransportErrorCode.keyUpdateError.value, 0x0e);
      expect(QuicTransportErrorCode.aeadLimitReached.value, 0x0f);
      expect(QuicTransportErrorCode.noViablePath.value, 0x10);
    });

    test('fromValue returns correct enum for known codes', () {
      expect(QuicTransportErrorCode.fromValue(0x00),
          QuicTransportErrorCode.noError);
      expect(QuicTransportErrorCode.fromValue(0x0a),
          QuicTransportErrorCode.protocolViolation);
      expect(QuicTransportErrorCode.fromValue(0x10),
          QuicTransportErrorCode.noViablePath);
    });

    test('fromValue returns null for unknown codes', () {
      expect(QuicTransportErrorCode.fromValue(0x99), isNull);
      expect(QuicTransportErrorCode.fromValue(0x11), isNull);
    });
  });
}

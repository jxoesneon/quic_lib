import 'package:test/test.dart';
import 'package:quic_lib/src/crypto/tls/finished_message.dart';

void main() {
  group('FinishedMessage', () {
    test('serialize round-trip with parse', () {
      final verifyData = List<int>.generate(32, (i) => i);
      final original = FinishedMessage(verifyData: verifyData);

      final serialized = original.serialize();
      final parsed = FinishedMessage.parse(serialized);

      expect(parsed.verifyData, equals(verifyData));
    });

    test('verifyData length preserved', () {
      final verifyData48 = List<int>.generate(48, (i) => i * 2 % 256);
      final msg = FinishedMessage(verifyData: verifyData48);

      final serialized = msg.serialize();
      expect(serialized.length, equals(48));

      final parsed = FinishedMessage.parse(serialized);
      expect(parsed.verifyData.length, equals(48));
      expect(parsed.verifyData, equals(verifyData48));
    });

    test('different data produces different serialization', () {
      final dataA = List<int>.generate(32, (i) => i);
      final dataB = List<int>.generate(32, (i) => 31 - i);

      final msgA = FinishedMessage(verifyData: dataA);
      final msgB = FinishedMessage(verifyData: dataB);

      final serializedA = msgA.serialize();
      final serializedB = msgB.serialize();

      expect(serializedA, isNot(equals(serializedB)));
    });
  });
}

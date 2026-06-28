import 'package:test/test.dart';
import 'package:quic_lib/src/security/anti_amplification_limit.dart';

void main() {
  group('AntiAmplificationLimit', () {
    late AntiAmplificationLimit limit;

    setUp(() {
      limit = AntiAmplificationLimit();
    });

    test('canSend returns false initially when no bytes received', () {
      expect(limit.canSend(1), isFalse);
      expect(limit.sendBudget, equals(0));
    });

    test('budget increases after receiving bytes', () {
      limit.onBytesReceived(100);
      expect(limit.sendBudget, equals(300));
      expect(limit.canSend(300), isTrue);
      expect(limit.canSend(301), isFalse);
    });

    test('budget decreases after sending bytes', () {
      limit.onBytesReceived(100);
      limit.onBytesSent(50);
      expect(limit.sendBudget, equals(250));
      expect(limit.canSend(250), isTrue);
      expect(limit.canSend(251), isFalse);
    });

    test('validateAddress removes the limit', () {
      limit.onBytesReceived(100);
      limit.onBytesSent(250);
      expect(limit.canSend(100), isFalse);

      limit.validateAddress();
      expect(limit.canSend(100), isTrue);
      expect(limit.canSend(1000000), isTrue);
      expect(limit.sendBudget, equals(0x7FFFFFFFFFFFFFFF));
    });

    test('reset clears all state', () {
      limit.onBytesReceived(1000);
      limit.onBytesSent(500);
      limit.validateAddress();

      limit.reset();

      expect(limit.sendBudget, equals(0));
      expect(limit.canSend(1), isFalse);
      expect(limit.canSend(1000000), isFalse);
    });

    test('rejects negative byte counts', () {
      limit.onBytesReceived(100);
      expect(limit.sendBudget, equals(300));

      limit.onBytesSent(50);
      expect(limit.sendBudget, equals(250));

      // SECURITY FIX: negative bytes now throw ArgumentError.
      expect(() => limit.onBytesReceived(-10), throwsArgumentError);
      expect(() => limit.onBytesSent(-5), throwsArgumentError);
      // Zero is still a no-op.
      limit.onBytesReceived(0);
      limit.onBytesSent(0);
      expect(limit.sendBudget, equals(250));
    });

    test('budget never drops below zero', () {
      limit.onBytesSent(100);
      expect(limit.sendBudget, equals(0));
    });
  });
}

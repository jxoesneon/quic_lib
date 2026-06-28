import 'package:quic_lib/src/logging/quic_logger.dart';
import 'package:test/test.dart';

void main() {
  group('QuicLogger', () {
    test('log with custom sink captures message', () {
      String? captured;
      QuicLogger.setSink((msg) => captured = msg);
      QuicLogger.log('hello');
      expect(captured, equals('hello'));
    });

    test('setSink with null restores default sink', () {
      QuicLogger.setSink((msg) {});
      expect(QuicLogger.sink, isNotNull);
      QuicLogger.setSink(null);
      expect(QuicLogger.sink, isNotNull); // default sink is restored
      // Should not throw when logging with default sink
      QuicLogger.log('test default sink');
    });

    test('log forwards message to sink', () {
      final messages = <String>[];
      QuicLogger.setSink(messages.add);
      QuicLogger.log('msg1');
      QuicLogger.log('msg2');
      expect(messages, equals(['msg1', 'msg2']));
    });
  });
}

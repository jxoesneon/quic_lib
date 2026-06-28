import 'package:test/test.dart';
import 'package:quic_lib/src/streams/flow_controller.dart';

void main() {
  group('FlowController', () {
    test('initial window is available', () {
      final fc = FlowController(initialLimit: 1024);
      expect(fc.availableWindow, equals(1024));
      expect(fc.isBlocked, isFalse);
    });

    test('consume reduces window', () {
      final fc = FlowController(initialLimit: 1024);
      fc.consume(100);
      expect(fc.availableWindow, equals(924));
    });

    test('isBlocked when window exhausted', () {
      final fc = FlowController(initialLimit: 100);
      fc.consume(100);
      expect(fc.isBlocked, isTrue);
    });

    test('updateLimit increases window', () {
      final fc = FlowController(initialLimit: 100);
      fc.updateLimit(200);
      expect(fc.availableWindow, equals(200));
    });

    test('shouldUpdateWindow when half consumed', () {
      final fc = FlowController(initialLimit: 100);
      fc.consume(50);
      final newLimit = fc.shouldUpdateWindow(threshold: 50);
      expect(newLimit, isNotNull);
      expect(newLimit, equals(200));
    });

    test('reset restores initial state', () {
      final fc = FlowController(initialLimit: 100);
      fc.consume(50);
      fc.reset();
      expect(fc.availableWindow, equals(100));
    });
  });
}

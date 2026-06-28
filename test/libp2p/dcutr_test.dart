import 'dart:typed_data';

import 'package:quic_lib/src/libp2p/dcutr.dart';
import 'package:test/test.dart';

void main() {
  group('DCUtRMessage', () {
    test('CONNECT message serialize/parse round-trip', () {
      final addr = Uint8List.fromList([192, 168, 1, 1, 0, 80]);
      final msg = DCUtRMessage(
        type: DCUtRMessage.typeConnect,
        observedAddr: addr,
      );
      final serialized = msg.serialize();
      final parsed = DCUtRMessage.parse(serialized);
      expect(parsed, equals(msg));
      expect(parsed.type, equals(DCUtRMessage.typeConnect));
    });

    test('SYNC message serialize/parse round-trip', () {
      final addr = Uint8List.fromList([10, 0, 0, 1, 0, 443]);
      final msg = DCUtRMessage(
        type: DCUtRMessage.typeSync,
        observedAddr: addr,
      );
      final serialized = msg.serialize();
      final parsed = DCUtRMessage.parse(serialized);
      expect(parsed, equals(msg));
      expect(parsed.type, equals(DCUtRMessage.typeSync));
    });

    test('observed address preserved', () {
      final addr = Uint8List.fromList([1, 2, 3, 4, 5]);
      final msg = DCUtRMessage(
        type: DCUtRMessage.typeConnect,
        observedAddr: addr,
      );
      final serialized = msg.serialize();
      final parsed = DCUtRMessage.parse(serialized);
      expect(parsed.observedAddr, equals(addr));
    });
  });

  group('DCUtRHandler', () {
    final handler = DCUtRHandler();

    test('isValid returns true for CONNECT', () {
      final msg = handler.initiateConnect([1, 2, 3]);
      expect(handler.isValid(msg), isTrue);
    });

    test('isValid returns true for SYNC', () {
      final msg = handler.respondSync([4, 5, 6]);
      expect(handler.isValid(msg), isTrue);
    });

    test('isValid returns false for unknown type', () {
      final msg = DCUtRMessage(type: 0xFF, observedAddr: [1]);
      expect(handler.isValid(msg), isFalse);
    });

    test('initiateConnect creates CONNECT message', () {
      final addr = [192, 168, 0, 1];
      final msg = handler.initiateConnect(addr);
      expect(msg.type, equals(DCUtRMessage.typeConnect));
      expect(msg.observedAddr, equals(addr));
    });

    test('respondSync creates SYNC message', () {
      final addr = [10, 0, 0, 1];
      final msg = handler.respondSync(addr);
      expect(msg.type, equals(DCUtRMessage.typeSync));
      expect(msg.observedAddr, equals(addr));
    });
  });
}

import 'package:quic_lib/src/connection/connection_id_manager.dart';
import 'package:test/test.dart';

void main() {
  group('ConnectionIdManager', () {
    late ConnectionIdManager manager;

    setUp(() {
      manager = ConnectionIdManager();
    });

    test('issueNewId returns valid CID and token', () {
      final record = manager.issueNewId();

      expect(record.connectionId, isA<List<int>>());
      expect(record.connectionId.length, greaterThanOrEqualTo(8));
      expect(record.connectionId.length, lessThanOrEqualTo(20));

      expect(record.statelessResetToken, isA<List<int>>());
      expect(record.statelessResetToken.length, equals(16));

      expect(record.sequenceNumber, equals(0));
    });

    test('retireId removes CID from active set', () {
      final record = manager.issueNewId();
      final cid = record.connectionId;

      expect(manager.isValidId(cid), isTrue);
      expect(manager.activeIds.length, equals(1));

      manager.retireId(record.sequenceNumber);

      expect(manager.isValidId(cid), isFalse);
      expect(manager.activeIds, isEmpty);
      expect(manager.lookupSequenceNumber(cid), isNull);
    });

    test('isValidId returns correct boolean', () {
      final record = manager.issueNewId();
      final cid = record.connectionId;

      expect(manager.isValidId(cid), isTrue);
      expect(manager.isValidId(<int>[0, 0, 0, 0]), isFalse);
    });

    test('max active IDs enforced', () {
      // Issue exactly maxActiveIds (8) CIDs.
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        manager.issueNewId();
      }
      expect(
          manager.activeIds.length, equals(ConnectionIdManager.maxActiveIds));

      // The next issueNewId should throw.
      expect(
        () => manager.issueNewId(),
        throwsA(isA<StateError>()),
      );
    });

    test('same CID not issued twice', () {
      final issued = <String>{};
      for (var i = 0; i < ConnectionIdManager.maxActiveIds; i++) {
        final record = manager.issueNewId();
        final key = record.connectionId
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();
        expect(issued.contains(key), isFalse, reason: 'Duplicate CID detected');
        issued.add(key);
      }
    });

    test('retirePriorTo retires older CIDs', () {
      final r0 = manager.issueNewId();
      final r1 = manager.issueNewId();
      final r2 = manager.issueNewId();

      expect(manager.activeIds.length, equals(3));

      // Issue a new CID with retirePriorTo = 2.
      final r3 = manager.issueNewId(retirePriorTo: 2);

      expect(manager.isValidId(r0.connectionId), isFalse);
      expect(manager.isValidId(r1.connectionId), isFalse);
      expect(manager.isValidId(r2.connectionId), isTrue);
      expect(manager.isValidId(r3.connectionId), isTrue);
    });

    test('sequence numbers are monotonically increasing', () {
      final r0 = manager.issueNewId();
      final r1 = manager.issueNewId();
      final r2 = manager.issueNewId();

      expect(r1.sequenceNumber, equals(r0.sequenceNumber + 1));
      expect(r2.sequenceNumber, equals(r1.sequenceNumber + 1));
    });
  });
}

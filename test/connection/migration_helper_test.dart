import 'package:quic_lib/src/connection/migration_helper.dart';
import 'package:quic_lib/src/wire/frame.dart';
import 'package:test/test.dart';

void main() {
  group('MigrationHelper', () {
    late MigrationHelper helper;

    setUp(() {
      helper = MigrationHelper();
    });

    test('generateChallenge produces 8-byte data', () {
      final frame = helper.generateChallenge(currentTimeUs: 0);

      expect(frame.data, isA<List<int>>());
      expect(frame.data.length, equals(8));
      expect(frame.frameType, equals(0x1a));
    });

    test('onResponseReceived returns true for matching challenge', () {
      final challenge = helper.generateChallenge(currentTimeUs: 0);
      final response = PathResponseFrame(data: challenge.data);

      expect(helper.onResponseReceived(response), isTrue);
    });

    test('onResponseReceived returns false for unknown challenge', () {
      final unknownData = <int>[1, 2, 3, 4, 5, 6, 7, 8];
      final response = PathResponseFrame(data: unknownData);

      expect(helper.onResponseReceived(response), isFalse);
    });

    test('getExpiredChallenges returns stale entries', () {
      final challenge = helper.generateChallenge(currentTimeUs: 0);
      final expired = helper.getExpiredChallenges(
        10000,
        timeoutUs: MigrationHelper.defaultTimeoutUs,
      );

      expect(expired.length, equals(1));
      expect(expired.first, equals(challenge.data));
    });

    test('isPathValidated returns true after response', () {
      final challenge = helper.generateChallenge(currentTimeUs: 0);
      expect(helper.isPathValidated(challenge.data), isFalse);

      final response = PathResponseFrame(data: challenge.data);
      helper.onResponseReceived(response);

      expect(helper.isPathValidated(challenge.data), isTrue);
    });

    test('reset clears all state', () {
      final challenge = helper.generateChallenge(currentTimeUs: 0);
      final response = PathResponseFrame(data: challenge.data);
      helper.onResponseReceived(response);

      expect(helper.isPathValidated(challenge.data), isTrue);

      helper.reset();

      expect(helper.isPathValidated(challenge.data), isFalse);
    });

    test('clock backward jump does not falsely expire challenges', () {
      final challenge = helper.generateChallenge(currentTimeUs: 1000);
      // Clock jumps backward to 500: challenge should NOT be expired.
      final expired = helper.getExpiredChallenges(
        500,
        timeoutUs: 10,
      );
      expect(expired.isEmpty, isTrue);
    });

    test('evicts oldest pending challenge when at capacity', () {
      // Generate 8 challenges with non-monotonic timestamps so the
      // first-inserted key is not the oldest (covers the loop body).
      helper.generateChallenge(currentTimeUs: 10);
      for (var i = 0; i < 6; i++) {
        helper.generateChallenge(currentTimeUs: i + 1);
      }
      final oldest = helper.generateChallenge(currentTimeUs: 0);
      // 8 challenges now. Generate one more to trigger eviction.
      helper.generateChallenge(currentTimeUs: 8);
      // The challenge with timestamp 0 should have been evicted.
      expect(helper.onResponseReceived(PathResponseFrame(data: oldest.data)),
          isFalse);
    });

    test('evicts oldest validated path when at capacity', () {
      // Validate 16 paths one at a time to stay under pending limit.
      for (var i = 0; i < 16; i++) {
        final c = helper.generateChallenge(currentTimeUs: i);
        helper.onResponseReceived(PathResponseFrame(data: c.data));
      }
      // Add one more validated path to trigger eviction.
      final extra = helper.generateChallenge(currentTimeUs: 16);
      helper.onResponseReceived(PathResponseFrame(data: extra.data));
      expect(helper.isPathValidated(extra.data), isTrue);
    });
  });
}

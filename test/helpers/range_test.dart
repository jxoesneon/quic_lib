import 'package:test/test.dart';
import 'range.dart';

void main() {
  group('listEquals', () {
    test('returns true for identical lists', () {
      expect(listEquals([1, 2, 3], [1, 2, 3]), isTrue);
    });

    test('returns true for empty lists', () {
      expect(listEquals([], []), isTrue);
    });

    test('returns false for different lengths', () {
      expect(listEquals([1, 2], [1, 2, 3]), isFalse);
    });

    test('returns false for different contents', () {
      expect(listEquals([1, 2, 3], [1, 2, 4]), isFalse);
    });
  });

  group('concat', () {
    test('concatenates multiple parts', () {
      expect(concat([[1, 2], [3], [4, 5, 6]]), [1, 2, 3, 4, 5, 6]);
    });

    test('returns empty list for no parts', () {
      expect(concat([]), isEmpty);
    });

    test('returns empty list for all empty parts', () {
      expect(concat([[], [], []]), isEmpty);
    });
  });
}

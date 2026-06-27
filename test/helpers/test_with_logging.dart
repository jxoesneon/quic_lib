import 'package:test/test.dart' as test;

/// Wraps a test with structured logging for debugging.
///
/// Prints `[START] <name>` before running the body, `[PASS] <name>` on
/// success, and `[FAIL] <name>: <error>` on failure.
///
/// Usage:
/// ```dart
/// testWithLogging('hex decode works', () {
///   expect(hexDecode('00'), [0]);
/// });
/// ```
void testWithLogging(String name, dynamic Function() body) {
  test.test(name, () {
    // ignore: avoid_print
    print('[START] $name');
    try {
      final result = body();
      if (result is Future) {
        return result.then((_) {
          // ignore: avoid_print
          print('[PASS] $name');
        }).catchError((Object e) {
          // ignore: avoid_print
          print('[FAIL] $name: $e');
          throw e;
        });
      }
      // ignore: avoid_print
      print('[PASS] $name');
    } catch (e) {
      // ignore: avoid_print
      print('[FAIL] $name: $e');
      rethrow;
    }
  });
}

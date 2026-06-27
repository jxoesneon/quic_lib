import 'test_with_logging.dart';

/// These are not wrapped in `group`/`test` because `testWithLogging`
/// registers top-level tests itself.  Calling it inside another `test()`
/// block would throw "Can't call test() once tests have begun running."
void main() {
  // Verifies that testWithLogging can be invoked for a passing test.
  testWithLogging('testWithLogging runs body on success', () {
    assert(1 + 1 == 2);
  });

  // Verifies that async bodies work.
  testWithLogging('testWithLogging supports async bodies', () async {
    await Future.delayed(Duration(milliseconds: 1));
    assert(true);
  });
}

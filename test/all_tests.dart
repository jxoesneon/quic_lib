/// Test suite aggregator.
///
/// Run with:
///   dart test test/all_tests.dart
///
/// All helper self-tests and subsystem tests are imported here so a single
/// command exercises the entire suite.

// Helper self-tests
import 'helpers/hex_test.dart' as hex_test;
import 'helpers/range_test.dart' as range_test;
import 'helpers/varint_test_cases_test.dart' as varint_test_cases_test;
import 'helpers/mock_udp_socket_test.dart' as mock_udp_socket_test;
import 'helpers/mock_crypto_backend_test.dart' as mock_crypto_backend_test;
import 'helpers/test_with_logging_test.dart' as test_with_logging_test;

// Subsystem tests
import 'crypto/crypto_backend_test.dart' as crypto_backend_test;

void main() {
  hex_test.main();
  range_test.main();
  varint_test_cases_test.main();
  mock_udp_socket_test.main();
  mock_crypto_backend_test.main();
  test_with_logging_test.main();
  crypto_backend_test.main();
}

/// Test suite aggregator.
///
/// Run with:
///   dart test test/all_tests.dart
///
/// All helper self-tests and subsystem tests are imported here so a single
/// command exercises the entire suite.

// Helper self-tests
import 'helpers/hex_test.dart' as hex_test;
import 'helpers/varint_test_cases_test.dart' as varint_test_cases_test;
import 'helpers/mock_udp_socket_test.dart' as mock_udp_socket_test;
import 'helpers/mock_crypto_backend_test.dart' as mock_crypto_backend_test;
import 'helpers/test_with_logging_test.dart' as test_with_logging_test;

// Subsystem tests
import 'crypto/crypto_backend_test.dart' as crypto_backend_test;
import 'crypto/tls/ocsp_crl_test.dart' as ocsp_crl_test;
import 'io/udp_rate_limiter_test.dart' as udp_rate_limiter_test;
import 'wire/quic_v2_test.dart' as quic_v2_test;

// End-to-end tests
import 'e2e/http3_e2e_test.dart' as http3_e2e_test;

// HTTP/3 server push tests
import 'http3/server_push_test.dart' as server_push_test;

// Interop tests
import 'interop/interop_test.dart' as interop_test;

// WebTransport tests
import 'webtransport/flow_control_test.dart' as flow_control_test;

void main() {
  hex_test.main();
  varint_test_cases_test.main();
  mock_udp_socket_test.main();
  mock_crypto_backend_test.main();
  test_with_logging_test.main();
  crypto_backend_test.main();
  ocsp_crl_test.main();
  udp_rate_limiter_test.main();
  quic_v2_test.main();
  http3_e2e_test.main();
  server_push_test.main();
  interop_test.main();
  flow_control_test.main();
}

// Runner for the host-native AsyncTCP tests.
//
//   ./asynctcp_tests            run everything
//   ./asynctcp_tests <substr>   run only tests whose name contains <substr>
//   ASYNCTCP_TEST_VERBOSE=1     also print the library's log_* output

#include "test_framework.h"

#include <cstdlib>
#include <cstring>
#include <exception>

#include "mocks/mock_lwip.h"
#include "mocks/mock_rtos.h"

namespace testfw {

int g_failures = 0;
const char *g_current = nullptr;

std::vector<TestCase> &registry() {
  static std::vector<TestCase> r;
  return r;
}

void report_failure(const char *file, int line, const char *expr, const std::string &detail) {
  g_failures++;
  const char *base = strrchr(file, '/');
  fprintf(stderr, "    FAIL %s:%d: %s", base ? base + 1 : file, line, expr);
  if (!detail.empty()) {
    fprintf(stderr, "  (%s)", detail.c_str());
  }
  fputc('\n', stderr);
}

int run_all(int argc, char **argv) {
  const char *filter = (argc > 1) ? argv[1] : nullptr;

  unsigned passed = 0, failed = 0, xfailed = 0, xpassed = 0, skipped = 0;

  for (const TestCase &t : registry()) {
    if (filter && !strstr(t.name, filter)) {
      skipped++;
      continue;
    }

    // Every test starts from a clean stack.
    mocklwip::reset();
    mockrtos::reset();
    mockclock::reset();

    g_failures = 0;
    g_current = t.name;
    printf("  %-52s ", t.name);
    fflush(stdout);

    try {
      t.fn();
    } catch (const std::exception &e) {
      report_failure(__FILE__, __LINE__, "unexpected exception", e.what());
    } catch (...) {
      report_failure(__FILE__, __LINE__, "unexpected exception", "unknown");
    }

    if (mockrtos::null_semaphores()) {
      report_failure(__FILE__, __LINE__, "semaphore used before it was created", t.name);
    }

    if (t.known_fail) {
      if (g_failures) {
        xfailed++;
        printf("xfail (known issue)\n");
      } else {
        xpassed++;
        printf("XPASS -- known issue appears fixed, promote to TEST()\n");
      }
    } else if (g_failures) {
      failed++;
      printf("FAILED (%d check%s)\n", g_failures, g_failures == 1 ? "" : "s");
    } else {
      passed++;
      printf("ok\n");
    }

    // Drop anything the test left behind so the next one starts clean.
    mocklwip::reset();
  }

  printf("\n%u passed, %u failed", passed, failed);
  if (xfailed) {
    printf(", %u known-fail", xfailed);
  }
  if (xpassed) {
    printf(", %u XPASS", xpassed);
  }
  if (skipped) {
    printf(", %u filtered out", skipped);
  }
  printf("\n");

  return failed ? 1 : 0;
}

}  // namespace testfw

int main(int argc, char **argv) {
  printf("AsyncTCP host-native tests\n\n");
  return testfw::run_all(argc, argv);
}

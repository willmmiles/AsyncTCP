// A ~100 line assert-based test runner. No framework, no dependencies.
//
//   TEST(name) { ... CHECK(cond); CHECK_EQ(a, b); ... }
//   TEST_KNOWN_FAIL(name) { ... }   // expected to fail; an unexpected pass is
//                                   // reported as XPASS but does not fail the run
//
// Tests are registered by a static initialiser and run in link order.
#ifndef ASYNCTCP_TEST_FRAMEWORK_H
#define ASYNCTCP_TEST_FRAMEWORK_H

#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace testfw {

struct TestCase {
  const char *name;
  void (*fn)();
  bool known_fail;
};

std::vector<TestCase> &registry();
// Incremented by every failing CHECK in the test currently running.
extern int g_failures;
extern const char *g_current;

struct Registrar {
  Registrar(const char *name, void (*fn)(), bool known_fail) {
    registry().push_back(TestCase{name, fn, known_fail});
  }
};

void report_failure(const char *file, int line, const char *expr, const std::string &detail);

template<typename T> std::string to_str(const T &v) {
  if constexpr (std::is_same_v<T, bool>) {
    return v ? "true" : "false";
  } else if constexpr (std::is_same_v<T, std::string>) {
    return "\"" + v + "\"";
  } else if constexpr (std::is_same_v<std::decay_t<T>, const char *> || std::is_same_v<std::decay_t<T>, char *>) {
    return v ? std::string("\"") + v + "\"" : std::string("(null)");
  } else if constexpr (std::is_pointer_v<T>) {
    char b[32];
    snprintf(b, sizeof(b), "%p", (const void *)v);
    return b;
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string((long long)v);
  } else {
    return std::to_string(v);
  }
}

int run_all(int argc, char **argv);

}  // namespace testfw

#define TEST_IMPL_(name, known_fail)                                      \
  static void name();                                                     \
  static testfw::Registrar name##_registrar_(#name, &name, known_fail);   \
  static void name()

#define TEST(name) TEST_IMPL_(name, false)
#define TEST_KNOWN_FAIL(name) TEST_IMPL_(name, true)

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) {                                                        \
      testfw::report_failure(__FILE__, __LINE__, #cond, std::string());   \
    }                                                                     \
  } while (0)

#define CHECK_EQ(a, b)                                                    \
  do {                                                                    \
    auto a_ = (a);                                                        \
    auto b_ = (b);                                                        \
    if (!(a_ == b_)) {                                                    \
      testfw::report_failure(__FILE__, __LINE__, #a " == " #b,            \
                             "got " + testfw::to_str(a_) +                \
                               ", want " + testfw::to_str(b_));           \
    }                                                                     \
  } while (0)

#define CHECK_NE(a, b)                                                    \
  do {                                                                    \
    auto a_ = (a);                                                        \
    auto b_ = (b);                                                        \
    if (a_ == b_) {                                                       \
      testfw::report_failure(__FILE__, __LINE__, #a " != " #b,            \
                             "both " + testfw::to_str(a_));               \
    }                                                                     \
  } while (0)

#define CHECK_STREQ(a, b)                                                 \
  do {                                                                    \
    std::string a_(a);                                                    \
    std::string b_(b);                                                    \
    if (a_ != b_) {                                                       \
      testfw::report_failure(__FILE__, __LINE__, #a " == " #b,            \
                             "got " + testfw::to_str(a_) +                \
                               ", want " + testfw::to_str(b_));           \
    }                                                                     \
  } while (0)

#endif

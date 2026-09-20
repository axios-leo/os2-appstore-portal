// =============================================================================
// os2/platform/testing.hpp — 极简单测框架（零依赖；M1 视需要换 GoogleTest）
// 用法：OS2_TEST(name) { OS2_ASSERT(cond); OS2_ASSERT_EQ(a, b); }
//       main 里 return os2::testing::run_all();
// =============================================================================
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace os2::testing {

struct Case { std::string name; std::function<void()> fn; };
inline std::vector<Case>& cases() { static std::vector<Case> v; return v; }
inline int& failures() { static int f = 0; return f; }
inline std::string& current() { static std::string c; return c; }

struct Registrar {
  Registrar(std::string name, std::function<void()> fn) {
    cases().push_back({std::move(name), std::move(fn)});
  }
};

inline void fail(const std::string& expr, const char* file, int line) {
  ++failures();
  std::cerr << "[FAIL] " << current() << " @ " << file << ":" << line
            << "  " << expr << "\n";
}

inline int run_all() {
  for (auto& c : cases()) {
    current() = c.name;
    int before = failures();
    c.fn();
    std::cerr << (failures() == before ? "[ ok ] " : "[FAIL] ") << c.name << "\n";
  }
  std::cerr << cases().size() << " test(s), " << failures() << " failure(s)\n";
  return failures() == 0 ? 0 : 1;
}

}  // namespace os2::testing

#define OS2_TEST(name)                                             \
  static void os2_test_##name();                                   \
  static ::os2::testing::Registrar os2_reg_##name{#name, os2_test_##name}; \
  static void os2_test_##name()

#define OS2_ASSERT(cond)                                           \
  do { if (!(cond)) ::os2::testing::fail(#cond, __FILE__, __LINE__); } while (0)

#define OS2_ASSERT_EQ(a, b)                                        \
  do {                                                             \
    auto va = (a); auto vb = (b);                                  \
    if (!(va == vb)) {                                             \
      std::ostringstream o; o << #a " == " #b " (got: " << va << " vs " << vb << ")"; \
      ::os2::testing::fail(o.str(), __FILE__, __LINE__);           \
    }                                                              \
  } while (0)

// L0 util — 环境变量读取（带默认值）
#pragma once
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include "util/fs.hpp"

namespace zproxy::util::env {

inline std::string str(const char* name, const std::string& dflt) {
  auto v = fs::getenv_str(name);
  return v ? *v : dflt;
}
inline std::optional<std::string> str_opt(const char* name) { return fs::getenv_str(name); }

inline int64_t i64(const char* name, int64_t dflt) {
  auto v = fs::getenv_str(name);
  if (!v) return dflt;
  char* end = nullptr;
  long long r = std::strtoll(v->c_str(), &end, 10);
  if (end == v->c_str() || *end != '\0') return dflt;
  return r;
}

inline bool boolean(const char* name, bool dflt) {
  auto v = fs::getenv_str(name);
  if (!v) return dflt;
  std::string s = *v;
  for (auto& c : s) c = std::tolower((unsigned char)c);
  return s == "1" || s == "true" || s == "yes" || s == "on";
}

} // namespace zproxy::util::env

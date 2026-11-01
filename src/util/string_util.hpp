// L0 util — 字符串工具
#pragma once
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace zproxy::util {

inline bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }
inline bool ends_with(const std::string& s, const std::string& p) {
  return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}
inline std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}
inline std::string trim(const std::string& s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}
inline std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::string cur;
  for (char c : s) {
    if (c == delim) { out.push_back(cur); cur.clear(); } else cur += c;
  }
  out.push_back(cur);
  return out;
}
inline std::string replace_all(std::string s, const std::string& from, const std::string& to) {
  if (from.empty()) return s;
  size_t pos = 0;
  while ((pos = s.find(from, pos)) != std::string::npos) { s.replace(pos, from.size(), to); pos += to.size(); }
  return s;
}
inline bool contains(const std::string& hay, const std::string& needle) { return hay.find(needle) != std::string::npos; }
inline bool iequals(const std::string& a, const std::string& b) { return to_lower(a) == to_lower(b); }

} // namespace zproxy::util

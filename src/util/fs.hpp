// L0 util — 文件系统（读/写/mtime/路径展开）
#pragma once
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace zproxy::util::fs {

inline std::optional<std::string> getenv_str(const char* name) {
  const char* v = std::getenv(name);
  if (!v || !*v) return std::nullopt;
  return std::string(v);
}

inline std::string home_dir() {
  auto h = getenv_str("HOME");
  return h.value_or("/");
}

inline std::string cwd() {
  char buf[PATH_MAX];
  if (::getcwd(buf, sizeof(buf))) return buf;
  return ".";
}

inline std::string expanduser(const std::string& p) {
  if (p.size() >= 2 && p[0] == '~' && p[1] == '/') return home_dir() + p.substr(1);
  return p;
}

inline std::string join(const std::string& a, const std::string& b) {
  if (a.empty()) return b;
  if (b.empty()) return a;
  if (b[0] == '/') return b;
  return a.back() == '/' ? a + b : a + "/" + b;
}

inline bool exists(const std::string& p) { return ::access(p.c_str(), F_OK) == 0; }

inline bool is_file(const std::string& p) {
  struct stat st{};
  return ::stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

inline bool is_dir(const std::string& p) {
  struct stat st{};
  return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

// 毫秒精度 mtime（热重载判据）；不存在返回 -1
inline double mtime_ms(const std::string& p) {
  struct stat st{};
  if (::stat(p.c_str(), &st) != 0) return -1;
#if defined(__APPLE__)
  double sec = static_cast<double>(st.st_mtimespec.tv_sec);
  double nsec = static_cast<double>(st.st_mtimespec.tv_nsec);
#else
  double sec = static_cast<double>(st.st_mtim.tv_sec);
  double nsec = static_cast<double>(st.st_mtim.tv_nsec);
#endif
  return sec * 1000.0 + nsec / 1e6;
}

inline std::optional<std::string> read_file(const std::string& p) {
  std::ifstream f(p, std::ios::binary);
  if (!f) return std::nullopt;
  f.seekg(0, std::ios::end);
  auto sz = f.tellg();
  if (sz <= 0) return std::string();
  std::string out;
  out.resize((size_t)sz);
  f.seekg(0);
  f.read(out.data(), sz);
  out.resize((size_t)f.gcount());
  return out;
}

inline bool write_file(const std::string& p, const std::string& data) {
  std::string tmp = p + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << data;
    if (!f.good()) { f.close(); ::unlink(tmp.c_str()); return false; }
  }
  if (::rename(tmp.c_str(), p.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
  return true;
}

// 列目录（不递归）文件名
inline std::vector<std::string> list_dir(const std::string& dir) {
  std::vector<std::string> out;
  DIR* d = ::opendir(dir.c_str());
  if (!d) return out;
  while (struct dirent* e = ::readdir(d)) {
    std::string n = e->d_name;
    if (n == "." || n == "..") continue;
    out.push_back(n);
  }
  ::closedir(d);
  return out;
}

} // namespace zproxy::util::fs

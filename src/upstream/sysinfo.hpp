// L4 upstream — 宿主机特征（uname / 时区），WAF 特征头数据源
#pragma once
#include <sys/utsname.h>
#include <fstream>
#include <string>
#include "util/string_util.hpp"

namespace zproxy::upstream::sysinfo {

// os.release()：uname release（macOS 如 "24.6.0"）
inline const std::string& kernel_release() {
  static const std::string v = [] {
    utsname u{};
    if (uname(&u) != 0) return std::string("unknown");
    return std::string(u.release);
  }();
  return v;
}

// os.version()：uname version（macOS 内核构建串）
inline const std::string& kernel_version() {
  static const std::string v = [] {
    utsname u{};
    if (uname(&u) != 0) return std::string("unknown");
    std::string s = u.version;
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
  }();
  return v;
}

// Intl.DateTimeFormat().resolvedOptions().timeZone 的近似：/etc/localtime 符号链接目标里取 zoneinfo/ 后段
inline const std::string& tz_name() {
  static const std::string v = [] {
    std::error_code ec_dummy;
    char buf[1024];
    ssize_t n = ::readlink("/etc/localtime", buf, sizeof(buf) - 1);
    if (n > 0) {
      buf[n] = '\0';
      std::string t(buf);
      auto pos = t.find("zoneinfo/");
      if (pos != std::string::npos) return t.substr(pos + 9);
    }
    return std::string("Asia/Shanghai");
  }();
  return v;
}

// `${process.platform}-${process.arch}`
inline const std::string& process_platform_arch() {
  static const std::string v = [] {
    utsname u{};
    if (uname(&u) != 0) return std::string("unknown-unknown");
    std::string p = std::string(u.sysname) == "Darwin" ? "darwin"
                  : std::string(u.sysname) == "Linux"  ? "linux" : std::string(u.sysname);
    std::string a = u.machine;
    if (a == "arm64" || a == "aarch64") a = "arm64";
    else if (a == "x86_64") a = "x64";
    return p + "-" + a;
  }();
  return v;
}

} // namespace zproxy::upstream::sysinfo

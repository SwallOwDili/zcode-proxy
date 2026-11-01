// L0 util — stderr 日志（与 Node 版一致：日志走 stderr）
#pragma once
#include <cstdio>
#include <string>
#include "util/time_util.hpp"

namespace zproxy::util {

inline void log(const std::string& msg) { std::fprintf(stderr, "[%s] %s\n", time_util::now_hms().c_str(), msg.c_str()); }

} // namespace zproxy::util

// L0 util — 时间工具（含北京时区日戳，usage 计费/claim 状态依赖）
#pragma once
#include <chrono>
#include <cstdint>
#include <ctime>
#include <string>

namespace zproxy::util::time_util {

inline int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

inline int64_t now_sec() { return now_ms() / 1000; }

inline std::tm local_tm_at(int64_t ms, int tz_offset_minutes) {
  std::time_t t = static_cast<std::time_t>(ms / 1000 + tz_offset_minutes * 60);
  std::tm tm{};
  gmtime_r(&t, &tm);
  return tm;
}

// 北京时间（UTC+8）日戳 YYYY-MM-DD —— usage.json 的 day key
inline std::string beijing_date(int64_t ms = now_ms()) {
  std::tm tm = local_tm_at(ms, 8 * 60);
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
  return buf;
}

// 北京时间 MMDD —— claim-state.json 的 day key（无年份）
inline std::string beijing_mmdd(int64_t ms = now_ms()) {
  std::tm tm = local_tm_at(ms, 8 * 60);
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%02d%02d", tm.tm_mon + 1, tm.tm_mday);
  return buf;
}

// 本机时区 HH:MM:SS —— recent 列表用
inline std::string now_hms() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

inline int local_hour() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  localtime_r(&t, &tm);
  return tm.tm_hour;
}

// 本机时区相对 UTC 的偏移（分钟，东区为正）
inline int local_tz_offset_minutes() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  localtime_r(&t, &tm);
  return static_cast<int>(tm.tm_gmtoff) / 60;
}

} // namespace zproxy::util::time_util

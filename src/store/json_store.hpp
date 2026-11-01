// L2 store — JSON 状态文件基类：mtime 热重载 + 线程安全 + 原子写
//
// 锁约定：read_nolock()/write_nolock() 假定调用方已持 mu_（或单线程）；
//         read()/write() 是自加锁的便捷封装。子类若已持锁必须用 nolock 变体。
#pragma once
#include <mutex>
#include <optional>
#include <string>
#include "nlohmann/json.hpp"
#include "util/fs.hpp"
#include "util/log.hpp"

namespace zproxy::store {

class JsonFile {
public:
  explicit JsonFile(std::string path) : path_(std::move(path)) {}

  const std::string& path() const { return path_; }

  // 文件 mtime 是否变化
  bool changed_on_disk() {
    double m = util::fs::mtime_ms(path_);
    if (m < 0) return false; // 不存在 → 维持内存态（对齐 Node try/catch 行为）
    return m != last_mtime_;
  }

protected:
  std::optional<nlohmann::json> read_nolock() {
    double m = util::fs::mtime_ms(path_);
    if (m >= 0) last_mtime_ = m;
    auto raw = util::fs::read_file(path_);
    if (!raw) return std::nullopt;
    try { return nlohmann::json::parse(*raw); } catch (...) { return std::nullopt; }
  }
  bool write_nolock(const nlohmann::json& j, int indent) {
    std::string data = j.dump(indent) + "\n";
    if (!util::fs::write_file(path_, data)) return false;
    double m = util::fs::mtime_ms(path_);
    if (m >= 0) last_mtime_ = m;
    return true;
  }
  std::optional<nlohmann::json> read() {
    std::lock_guard<std::mutex> lk(mu_);
    return read_nolock();
  }
  bool write(const nlohmann::json& j, int indent) {
    std::lock_guard<std::mutex> lk(mu_);
    return write_nolock(j, indent);
  }

  std::mutex mu_;
  std::string path_;
  double last_mtime_ = -1;
};

} // namespace zproxy::store

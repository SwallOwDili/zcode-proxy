// L2 store — usage.json：账号 × 模型 × 天 用量统计（与 Node 版磁盘格式逐字节兼容）
//
// 格式：{"days":{"YYYY-MM-DD":{"account\x01model":{"req":N,"in":N,"out":N,"cache":N}}}}
//   - day 为北京时间（UTC+8）；1 空格缩进 + 尾部换行；只保留最近 30 天
#pragma once
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>
#include "nlohmann/json.hpp"
#include "store/json_store.hpp"
#include "util/time_util.hpp"

namespace zproxy::store {

class UsageStore : public JsonFile {
public:
  explicit UsageStore(std::string path) : JsonFile(std::move(path)) {}
  ~UsageStore() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    if (saver_.joinable()) saver_.join();
    flush_now();
  }

  void start_saver() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!saver_.joinable()) saver_ = std::thread([this] { saver_loop(); });
  }

  // 记一次请求用量（线程安全；day 自动取北京日戳）
  void record(const std::string& account, const std::string& model,
              int64_t in_tok, int64_t out_tok, int64_t cache_tok) {
    auto clamp = [](int64_t x) { return x < 0 ? 0 : x; };
    std::string day = util::time_util::beijing_date();
    std::string key = account + "\x01" + model;
    {
      std::lock_guard<std::mutex> lk(mu_);
      ensure_loaded_nolock();
      auto& cell = data_["days"][day][key];
      if (!cell.is_object()) cell = {{"req", 0}, {"in", 0}, {"out", 0}, {"cache", 0}};
      cell["req"] = cell.value("req", (int64_t)0) + 1;
      cell["in"] = cell.value("in", (int64_t)0) + clamp(in_tok);
      cell["out"] = cell.value("out", (int64_t)0) + clamp(out_tok);
      cell["cache"] = cell.value("cache", (int64_t)0) + clamp(cache_tok);
      dirty_ = true;
    }
    cv_.notify_one();
  }

  nlohmann::json snapshot(int days = 7) {
    std::lock_guard<std::mutex> lk(mu_);
    ensure_loaded_nolock();
    nlohmann::json out = nlohmann::json::object();
    auto& days_obj = data_["days"];
    if (days_obj.is_object()) {
      for (auto it = days_obj.begin(); it != days_obj.end(); ++it) {
        if ((int)out.size() >= days) break;
        out[it.key()] = it.value();
      }
    }
    return out;
  }

  void flush_now() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!dirty_ && loaded_) return;
    ensure_loaded_nolock();
    prune_nolock();
    if (write_nolock(data_, 1)) dirty_ = false;
  }

private:
  void ensure_loaded_nolock() { // 需持锁
    if (loaded_) return;
    loaded_ = true;
    auto j = read_nolock();
    if (j && j->is_object() && j->contains("days") && (*j)["days"].is_object()) data_ = *j;
    else data_ = {{"days", nlohmann::json::object()}};
  }
  void prune_nolock() { // 需持锁；按 day 排序只留最近 30 天
    if (!data_["days"].is_object()) return;
    std::map<std::string, nlohmann::json> sorted;
    for (auto& [k, v] : data_["days"].items()) sorted[k] = v;
    while (sorted.size() > 30) sorted.erase(sorted.begin());
    data_["days"] = nlohmann::json::object();
    for (auto& [k, v] : sorted) data_["days"][k] = v;
  }
  void saver_loop() {
    std::unique_lock<std::mutex> lk(mu_);
    while (!stop_) {
      cv_.wait_for(lk, std::chrono::seconds(2));
      if (stop_) break;
      if (!dirty_ || !loaded_) continue;
      prune_nolock();
      if (write_nolock(data_, 1)) dirty_ = false;
    }
  }

  std::thread saver_;
  std::condition_variable cv_;
  nlohmann::json data_ = {{"days", nlohmann::json::object()}};
  bool loaded_ = false;
  bool dirty_ = false;
  bool stop_ = false;
};

} // namespace zproxy::store

// L3 domain — 最近请求环形列表（内存 ≤200 条）+ 实时广播钩子（SSE live 由 service 层挂）
#pragma once
#include <deque>
#include <functional>
#include <mutex>
#include "nlohmann/json.hpp"
#include "util/time_util.hpp"

namespace zproxy::domain {

struct RecentEntry {
  std::string at;      // HH:MM:SS
  int hour = 0;
  int64_t ts = 0;
  std::string kind;    // chat | chat/stream | messages | test
  std::string model, account, note;
  int status = 0;
  int64_t in_tok = 0, out_tok = 0, cache_tok = 0, ms = 0;
  bool has_ttft = false;
  int64_t ttft = 0;
};

class RecentLog {
public:
  using BroadcastFn = std::function<void(const nlohmann::json&)>;

  void record(RecentEntry e) {
    e.at = util::time_util::now_hms();
    e.hour = util::time_util::local_hour();
    e.ts = util::time_util::now_ms();
    nlohmann::json bc = {
      {"type", "req"}, {"ts", e.ts}, {"model", e.model}, {"account", e.account},
      {"status", e.status}, {"in", e.in_tok}, {"out", e.out_tok}, {"cache", e.cache_tok}, {"ms", e.ms},
    };
    std::lock_guard<std::mutex> lk(mu_);
    entries_.push_front(std::move(e));
    if (entries_.size() > 200) entries_.pop_back();
    if (broadcast_) broadcast_(bc);
  }
  void set_broadcast(BroadcastFn fn) {
    std::lock_guard<std::mutex> lk(mu_);
    broadcast_ = std::move(fn);
  }
  nlohmann::json to_json() {
    std::lock_guard<std::mutex> lk(mu_);
    nlohmann::json arr = nlohmann::json::array();
    for (auto& e : entries_) {
      nlohmann::json j = {
        {"at", e.at}, {"hour", e.hour}, {"ts", e.ts}, {"kind", e.kind},
        {"model", e.model}, {"account", e.account}, {"status", e.status},
        {"in", e.in_tok}, {"out", e.out_tok}, {"cache", e.cache_tok}, {"ms", e.ms},
      };
      if (!e.note.empty()) j["note"] = e.note;
      if (e.has_ttft) j["ttft"] = e.ttft;
      arr.push_back(std::move(j));
    }
    return {{"recent", arr}};
  }

private:
  std::mutex mu_;
  std::deque<RecentEntry> entries_;
  BroadcastFn broadcast_;
};

} // namespace zproxy::domain

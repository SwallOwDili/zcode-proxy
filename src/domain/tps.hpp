// L3 domain — TPS 统计：tokens ÷ 活跃区间并集（空闲不计入分母）
#pragma once
#include <algorithm>
#include <map>
#include <mutex>
#include <vector>
#include "nlohmann/json.hpp"
#include "util/time_util.hpp"

namespace zproxy::domain {

class TpsStats {
public:
  static constexpr int64_t kIdleMs = 15'000;

  int64_t run_start(const std::string& account) {
    std::lock_guard<std::mutex> lk(mu_);
    int64_t id = next_++;
    runs_[id] = Run{account, util::time_util::now_ms(), util::time_util::now_ms(), 0};
    return id;
  }
  void run_delta(int64_t id, int64_t tokens) {
    if (id <= 0) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(id);
    if (it == runs_.end()) return;
    it->second.out_tokens += tokens;
    it->second.end_ms = util::time_util::now_ms();
  }
  void run_end(int64_t id, int64_t real_out) {
    if (id <= 0) return;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(id);
    if (it == runs_.end()) return;
    if (real_out > 0) it->second.out_tokens = real_out;
    it->second.end_ms = util::time_util::now_ms();
  }

  nlohmann::json stats() {
    std::lock_guard<std::mutex> lk(mu_);
    int64_t now = util::time_util::now_ms();
    for (auto it = runs_.begin(); it != runs_.end();) {
      if (now - it->second.end_ms > 4 * kIdleMs) it = runs_.erase(it); else ++it;
    }
    // 活跃 run 按账号聚合：区间 + token 数
    std::map<std::string, std::vector<std::pair<int64_t, int64_t>>> iv;
    std::map<std::string, int64_t> toks;
    bool any_active = false;
    std::vector<std::pair<int64_t, int64_t>> all_iv;
    int64_t all_toks = 0;
    for (auto& [id, r] : runs_) {
      if (now - r.end_ms > kIdleMs) continue;
      any_active = true;
      iv[r.account].push_back({r.start_ms, r.end_ms});
      toks[r.account] += r.out_tokens;
      all_iv.push_back({r.start_ms, r.end_ms});
      all_toks += r.out_tokens;
    }
    if (!any_active) {
      return {{"idle", true}, {"activeSec", 0}, {"total", 0}, {"perAccount", nlohmann::json::object()}};
    }
    nlohmann::json per = nlohmann::json::object();
    for (auto& [acc, vec] : iv) {
      double sec = union_sec(vec);
      per[acc] = sec > 0 ? round1((double)toks[acc] / sec) : 0.0;
    }
    double total_sec = union_sec(all_iv);
    return {
      {"idle", false},
      {"activeSec", (int64_t)(total_sec + 0.5)},
      {"total", total_sec > 0 ? round1((double)all_toks / total_sec) : 0.0},
      {"perAccount", per},
    };
  }

private:
  struct Run { std::string account; int64_t start_ms, end_ms, out_tokens; };
  static double round1(double v) { return std::round(v * 10.0) / 10.0; }
  static double union_sec(std::vector<std::pair<int64_t, int64_t>> iv) {
    if (iv.empty()) return 0;
    std::sort(iv.begin(), iv.end());
    int64_t total = 0, cs = iv[0].first, ce = iv[0].second;
    for (size_t i = 1; i < iv.size(); i++) {
      if (iv[i].first <= ce) ce = std::max(ce, iv[i].second);
      else { total += ce - cs; cs = iv[i].first; ce = iv[i].second; }
    }
    total += ce - cs;
    return total / 1000.0;
  }

  std::mutex mu_;
  std::map<int64_t, Run> runs_;
  int64_t next_ = 1;
};

} // namespace zproxy::domain
